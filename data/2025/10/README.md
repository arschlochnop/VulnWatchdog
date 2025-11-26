# 2025年10月漏洞情报汇总

> 📅 统计周期: 2025-10-01 ~ 2025-10-30
> 📊 新增漏洞: **678** 个
> 🔥 高危漏洞: **583** 个

---

## 📊 漏洞类型分布

| 类型 | 数量 | 占比 |
|------|------|------|
| 远程代码执行 | 88 | 13.0% |
| 权限提升 | 42 | 6.2% |
| 身份验证绕过 | 36 | 5.3% |
| 远程代码执行 (RCE) | 34 | 5.0% |
| SQL注入 | 29 | 4.3% |
| 本地提权 | 23 | 3.4% |
| Use-After-Free | 17 | 2.5% |
| 反序列化漏洞 | 17 | 2.5% |
| 命令注入 | 16 | 2.4% |
| 认证绕过 | 13 | 1.9% |

---

## 📋 详细列表

### [CVE-2022-22536](CVE-2022-22536-ZZ-SOCMAP_CVE-2022-22536.md) 🔴 ✅

**名称:** CVE-2022-22536 - SAP NetWeaver Request Smuggling/Concatenation  
**类型:** HTTP Request Smuggling/Concatenation  
**风险:** 高危，可能导致信息泄露、权限提升、缓存投毒、拒绝服务  
**投毒风险:** 0%  
**发现时间:** 2025-10-31  
**POC仓库:** [CVE-2022-22536](https://github.com/ZZ-SOCMAP/CVE-2022-22536)  

---

### [CVE-2022-22536](CVE-2022-22536-tess-ss_SAP-memory-pipes-desynchronization-vulnerability-MPI-CVE-2022-22536.md) 🔴 ✅

**名称:** CVE-2022-22536 - SAP NetWeaver Request Smuggling/Concatenation  
**类型:** 请求走私/请求串联  
**风险:** 高危，可能导致信息泄露、权限提升、拒绝服务以及中间Web缓存投毒  
**投毒风险:** 10%  
**发现时间:** 2025-10-31  
**POC仓库:** [SAP-memory-pipes-desynchronization-vulnerability-MPI-CVE-2022-22536](https://github.com/tess-ss/SAP-memory-pipes-desynchronization-vulnerability-MPI-CVE-2022-22536)  

---

### [CVE-2022-22536](CVE-2022-22536-BecodoExploit-mrCAT_SAPGateBreaker-Exploit.md) 🔴 ✅

**名称:** CVE-2022-22536: SAP NetWeaver HTTP Request Smuggling  
**类型:** HTTP Request Smuggling  
**风险:** 高危，可导致权限绕过、缓存投毒、信息泄露、完全控制系统  
**投毒风险:** 10%  
**发现时间:** 2025-10-31  
**POC仓库:** [SAPGateBreaker-Exploit](https://github.com/BecodoExploit-mrCAT/SAPGateBreaker-Exploit)  

---

### [CVE-2022-22536](CVE-2022-22536-abrewer251_CVE-2022-22536_SAP_Request_Smuggling_Scanner.md) 🔴 ✅

**名称:** CVE-2022-22536 SAP Request Smuggling  
**类型:** 请求走私 (Request Smuggling)  
**风险:** 高危，可能导致权限提升、数据泄露、缓存投毒和拒绝服务  
**投毒风险:** 10%  
**发现时间:** 2025-10-31  
**POC仓库:** [CVE-2022-22536_SAP_Request_Smuggling_Scanner](https://github.com/abrewer251/CVE-2022-22536_SAP_Request_Smuggling_Scanner)  

---

### [CVE-2021-29447](CVE-2021-29447-ArtemCyberLab_Project-Project-Chimera-Exploiting-a-Modern-WordPress-XXE-to-Pillage-Secrets-.md) 🔴 ✅

**名称:** CVE-2021-29447 WordPress XXE  
**类型:** XML 外部实体注入 (XXE)  
**风险:** 高危，可能导致敏感信息泄露，包括数据库凭据，并最终导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-10-31  
**POC仓库:** [Project-Project-Chimera-Exploiting-a-Modern-WordPress-XXE-to-Pillage-Secrets-](https://github.com/ArtemCyberLab/Project-Project-Chimera-Exploiting-a-Modern-WordPress-XXE-to-Pillage-Secrets-)  

---

### [CVE-2021-29447](CVE-2021-29447-0xricksanchez_CVE-2021-29447.md) 🔴 ✅

**名称:** CVE-2021-29447 - WordPress Authenticated XXE attack in Media Library  
**类型:** XML External Entity (XXE) Injection  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-10-31  
**POC仓库:** [CVE-2021-29447](https://github.com/0xricksanchez/CVE-2021-29447)  

---

### [CVE-2021-3560](CVE-2021-3560-titusG85_SideWinder-Exploit.md) 🔴 ✅

**名称:** CVE-2021-3560 Polkit 权限提升  
**类型:** 权限提升  
**风险:** 高危，本地权限提升至 root  
**投毒风险:** 5%  
**发现时间:** 2025-10-31  
**POC仓库:** [SideWinder-Exploit](https://github.com/titusG85/SideWinder-Exploit)  

---

### [CVE-2021-3560](CVE-2021-3560-SeimuPVE_CVE-2021-3560_Polkit.md) 🔴 ✅

**名称:** CVE-2021-3560 Polkit 本地提权漏洞  
**类型:** 本地提权  
**风险:** 高危，可能导致本地用户获取Root权限  
**投毒风险:** 1%  
**发现时间:** 2025-10-31  
**POC仓库:** [CVE-2021-3560_Polkit](https://github.com/SeimuPVE/CVE-2021-3560_Polkit)  

---

### [CVE-2010-3863](CVE-2010-3863-sh1inroot-alt_shiro-cve-2010-3863.md) 🟡 ✅

**名称:** CVE-2010-3863 Apache Shiro 路径穿越  
**类型:** 路径穿越/安全绕过  
**风险:** 中危，可能导致未授权访问  
**投毒风险:** 0%  
**发现时间:** 2025-10-31  
**POC仓库:** [shiro-cve-2010-3863](https://github.com/sh1inroot-alt/shiro-cve-2010-3863)  

---

### [CVE-2025-11001](CVE-2025-11001-litolito54_CVE-2025-11001.md) 🔴 ✅

**名称:** CVE-2025-11001 - ZIP Slip 漏洞利用  
**类型:** ZIP Slip  
**风险:** 高危，可能导致任意文件写入  
**投毒风险:** 85%  
**发现时间:** 2025-10-31  
**POC仓库:** [CVE-2025-11001](https://github.com/litolito54/CVE-2025-11001)  

---

### [CVE-2025-48384](CVE-2025-48384-MarcoTondolo_cve-2025-48384-poc.md) 🔴 ✅

**名称:** CVE-2025-48384-Git-任意代码执行  
**类型:** 配置解析漏洞导致任意代码执行  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-10-31  
**POC仓库:** [cve-2025-48384-poc](https://github.com/MarcoTondolo/cve-2025-48384-poc)  

---

### [CVE-2025-4796](CVE-2025-4796-Pwdnx1337_CVE-2025-4796.md) 🔴 ✅

**名称:** CVE-2025-4796-Eventin-权限提升  
**类型:** 权限提升  
**风险:** 高危，可能导致账户被盗和任意代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-10-31  
**POC仓库:** [CVE-2025-4796](https://github.com/Pwdnx1337/CVE-2025-4796)  

---

### [CVE-2021-41773](CVE-2021-41773-adrianmafandy_CVE-2021-41773.md) 🔴 ✅

**名称:** CVE-2021-41773 - Apache HTTP Server 2.4.49 Path Traversal & RCE  
**类型:** 路径遍历和远程代码执行  
**风险:** 高危，可导致敏感信息泄露和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-10-31  
**POC仓库:** [CVE-2021-41773](https://github.com/adrianmafandy/CVE-2021-41773)  

---

### [CVE-2025-24893](CVE-2025-24893-Y2F05p2w_CVE-2025-24893.md) 🔴 ✅

**名称:** CVE-2025-24893-XWiki-RCE  
**类型:** 远程代码执行  
**风险:** 高危，未经身份验证的远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-10-31  
**POC仓库:** [CVE-2025-24893](https://github.com/Y2F05p2w/CVE-2025-24893)  

---

### [CVE-2025-49844](CVE-2025-49844-saneki_cve-2025-49844.md) 🔴 ✅

**名称:** CVE-2025-49844-Redis-Lua Use-After-Free  
**类型:** Use-After-Free  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-10-31  
**POC仓库:** [cve-2025-49844](https://github.com/saneki/cve-2025-49844)  

---

### [CVE-2025-26794](CVE-2025-26794-XploitGh0st_CVE-2025-26794-exploit.md) 🔴 ✅

**名称:** CVE-2025-26794-Exim-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-10-31  
**POC仓库:** [CVE-2025-26794-exploit](https://github.com/XploitGh0st/CVE-2025-26794-exploit)  

---

### [CVE-2024-48990](CVE-2024-48990-Loaxert_CVE-2024-48990-PoC.md) 🔴 ✅

**名称:** CVE-2024-48990-needrestart-权限提升  
**类型:** 权限提升  
**风险:** 高危，允许本地用户提升为root权限  
**投毒风险:** 0%  
**发现时间:** 2025-10-31  
**POC仓库:** [CVE-2024-48990-PoC](https://github.com/Loaxert/CVE-2024-48990-PoC)  

---

### [CVE-2021-41773](CVE-2021-41773-Mahfujurjust_CVE-2021-41773.md) 🔴 ✅

**名称:** CVE-2021-41773-Apache HTTP Server-路径遍历  
**类型:** 路径遍历  
**风险:** 高危，可能导致文件泄露和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-10-31  
**POC仓库:** [CVE-2021-41773](https://github.com/Mahfujurjust/CVE-2021-41773)  

---

### [CVE-2024-35374](CVE-2024-35374-Rikoot_CVE-2024-35374.md) 🔴 ✅

**名称:** CVE-2024-35374-Mocodo Online-命令注入  
**类型:** 命令注入  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-10-30  
**POC仓库:** [CVE-2024-35374](https://github.com/Rikoot/CVE-2024-35374)  

---

### [CVE-2025-24367](CVE-2025-24367-TheCyberGeek_CVE-2025-24367-Cacti-PoC.md) 🔴 ✅

**名称:** CVE-2025-24367 - Cacti Authenticated Graph Template RCE  
**类型:** 任意文件创建导致RCE  
**风险:** 高危，允许经过身份验证的用户在服务器上创建任意 PHP 脚本，从而导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-10-30  
**POC仓库:** [CVE-2025-24367-Cacti-PoC](https://github.com/TheCyberGeek/CVE-2025-24367-Cacti-PoC)  

---

### [CVE-2025-26625](CVE-2025-26625-Mitchellzhou1_CVE_2025_26625.md) 🔴 ✅

**名称:** CVE-2025-26625-git-lfs-symlink-arbitrary-write  
**类型:** 符号链接攻击/任意文件写入  
**风险:** 高危，可能导致任意文件写入，权限提升甚至远程代码执行。  
**投毒风险:** 10%  
**发现时间:** 2025-10-30  
**POC仓库:** [CVE_2025_26625](https://github.com/Mitchellzhou1/CVE_2025_26625)  

---

### [CVE-2025-10035](CVE-2025-10035-B1ack4sh_Blackash-CVE-2025-10035.md) 🔴 ✅

**名称:** CVE-2025-10035 - Fortra GoAnywhere MFT 反序列化漏洞  
**类型:** 反序列化漏洞  
**风险:** 高危，远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-10-30  
**POC仓库:** [Blackash-CVE-2025-10035](https://github.com/B1ack4sh/Blackash-CVE-2025-10035)  

---

### [CVE-2025-60503](CVE-2025-60503-H4zaz_CVE-2025-60503.md) 🔴 ✅

**名称:** CVE-2025-60503 - UltimatePOS Stored XSS  
**类型:** 存储型跨站脚本 (Stored XSS)  
**风险:** 高危，可能导致管理员账户劫持、敏感数据泄露和恶意代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-10-30  
**POC仓库:** [CVE-2025-60503](https://github.com/H4zaz/CVE-2025-60503)  

---

### [CVE-2025-61481](CVE-2025-61481-B1ack4sh_Blackash-CVE-2025-61481.md)  ✅

**名称:** CVE-2025-61481 - MikroTik WebFig 远程代码执行和凭据泄露  
**类型:** 远程代码执行 (RCE) 和凭据泄露  
**风险:** 严重，完全控制设备，凭据被盗，配置篡改  
**投毒风险:** 0%  
**发现时间:** 2025-10-30  
**POC仓库:** [Blackash-CVE-2025-61481](https://github.com/B1ack4sh/Blackash-CVE-2025-61481)  

---

### [CVE-2025-59287](CVE-2025-59287-0x7556_CVE-2025-59287.md) 🔴 ✅

**名称:** CVE-2025-59287 - Windows Server Update Service (WSUS) 远程代码执行漏洞  
**类型:** 反序列化  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-10-30  
**POC仓库:** [CVE-2025-59287](https://github.com/0x7556/CVE-2025-59287)  

---

### [CVE-2025-55752](CVE-2025-55752-B1ack4sh_Blackash-CVE-2025-55752.md) 🔴 ✅

**名称:** CVE-2025-55752 - Apache Tomcat 目录遍历/RCE  
**类型:** 目录遍历/远程代码执行  
**风险:** 高危，可能导致敏感信息泄露和远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-10-30  
**POC仓库:** [Blackash-CVE-2025-55752](https://github.com/B1ack4sh/Blackash-CVE-2025-55752)  

---

### [CVE-2024-48990](CVE-2024-48990-Mr-DJ_CVE-2024-48990.md) 🔴 ✅

**名称:** CVE-2024-48990-needrestart-本地权限提升  
**类型:** 本地权限提升  
**风险:** 高危，允许本地低权限用户以root权限执行任意代码  
**投毒风险:** 0%  
**发现时间:** 2025-10-30  
**POC仓库:** [CVE-2024-48990](https://github.com/Mr-DJ/CVE-2024-48990)  

---

### [CVE-2025-6440](CVE-2025-6440-Pwdnx1337_CVE-2025-6440.md) 🔴 ✅

**名称:** CVE-2025-6440-WooCommerce Designer Pro-任意文件上传  
**类型:** 任意文件上传  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-10-30  
**POC仓库:** [CVE-2025-6440](https://github.com/Pwdnx1337/CVE-2025-6440)  

---

### [CVE-2025-49844](CVE-2025-49844-B1ack4sh_Blackash-CVE-2025-49844.md) 🔴 

**名称:** CVE-2025-49844-Redis-Lua-Use-After-Free  
**类型:** Use-After-Free  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-10-30  
**POC仓库:** [Blackash-CVE-2025-49844](https://github.com/B1ack4sh/Blackash-CVE-2025-49844)  

---

### [CVE-2025-32463](CVE-2025-32463-muhammedkayag_CVE-2025-32463.md) 🔴 ✅

**名称:** CVE-2025-32463-Sudo-本地提权  
**类型:** 本地提权  
**风险:** 高危，本地用户可获取root权限  
**投毒风险:** 10%  
**发现时间:** 2025-10-30  
**POC仓库:** [CVE-2025-32463](https://github.com/muhammedkayag/CVE-2025-32463)  

---

### [CVE-2025-54957](CVE-2025-54957-AlphabugX_CVE-2025-54957.md) 🟡 

**名称:** CVE-2025-54957-Dolby UDC-越界写  
**类型:** 越界写  
**风险:** 中危，可能导致程序崩溃或信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-10-30  
**POC仓库:** [CVE-2025-54957](https://github.com/AlphabugX/CVE-2025-54957)  

---

### [CVE-2025-41656](CVE-2025-41656-wallyschag_CVE-2025-41656.md)  ✅

**名称:** CVE-2025-41656-Pilz-Node-RED未授权远程代码执行  
**类型:** 未授权远程代码执行  
**风险:** 严重，可能导致完全控制受影响设备  
**投毒风险:** 10%  
**发现时间:** 2025-10-29  
**POC仓库:** [CVE-2025-41656](https://github.com/wallyschag/CVE-2025-41656)  

---

### [CVE-2024-46256](CVE-2024-46256-barttran2k_POC_CVE-2024-46256.md) 🔴 ✅

**名称:** CVE-2024-46256-NginxProxyManager-命令注入  
**类型:** 命令注入  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-10-29  
**POC仓库:** [POC_CVE-2024-46256](https://github.com/barttran2k/POC_CVE-2024-46256)  

---

### [CVE-2024-46256](CVE-2024-46256-TranDongA3_Simulation_CVE-2024-46256.md) 🔴 ✅

**名称:** CVE-2024-46256-NginxProxyManager-命令注入  
**类型:** 命令注入  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-10-29  
**POC仓库:** [Simulation_CVE-2024-46256](https://github.com/TranDongA3/Simulation_CVE-2024-46256)  

---

### [CVE-2025-64095](CVE-2025-64095-callinston_CVE-2025-64095.md) 🔴 ✅

**名称:** CVE-2025-64095-DNN-任意文件上传/覆盖  
**类型:** 任意文件上传/覆盖  
**风险:** 高危，可能导致网站内容篡改、XSS攻击或远程代码执行  
**投毒风险:** 30%  
**发现时间:** 2025-10-29  
**POC仓库:** [CVE-2025-64095](https://github.com/callinston/CVE-2025-64095)  

---

### [CVE-2025-40778](CVE-2025-40778-nehkark_CVE-2025-40778.md) 🔴 ✅

**名称:** CVE-2025-40778: DNS Cache Poisoning via Additional Records Injection  
**类型:** DNS Cache Poisoning  
**风险:** 高危，可能导致透明钓鱼、企业网络入侵等  
**投毒风险:** 0%  
**发现时间:** 2025-10-29  
**POC仓库:** [CVE-2025-40778](https://github.com/nehkark/CVE-2025-40778)  

---

### [CVE-2025-63298](CVE-2025-63298-z3rObyte_CVE-2025-63298.md) 🔴 ✅

**名称:** CVE-2025-63298-Pet Grooming Management System-路径遍历文件删除  
**类型:** 路径遍历  
**风险:** 高危，可能导致任意文件删除和系统破坏  
**投毒风险:** 0%  
**发现时间:** 2025-10-29  
**POC仓库:** [CVE-2025-63298](https://github.com/z3rObyte/CVE-2025-63298)  

---

### [CVE-2025-31702](CVE-2025-31702-purpleghosts_CVE-2025-31702.md) 🟡 

**名称:** CVE-2025-31702-Dahua-权限提升  
**类型:** 权限提升  
**风险:** 中危，可导致管理员密码篡改，权限提升  
**投毒风险:** 10%  
**发现时间:** 2025-10-29  
**POC仓库:** [CVE-2025-31702](https://github.com/purpleghosts/CVE-2025-31702)  

---

### [CVE-2025-49844](CVE-2025-49844-elyasbassir_CVE-2025-49844.md) 🔴 ✅

**名称:** CVE-2025-49844-Redis Lua Use-After-Free 远程代码执行  
**类型:** Use-After-Free  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-10-29  
**POC仓库:** [CVE-2025-49844](https://github.com/elyasbassir/CVE-2025-49844)  

---

### [CVE-2020-14882](CVE-2020-14882-AshrafZaryouh_CVE-2020-14882.md) 🔴 ✅

**名称:** CVE-2020-14882 - Oracle WebLogic Server 远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，允许未授权的攻击者完全控制 WebLogic Server  
**投毒风险:** 10%  
**发现时间:** 2025-10-29  
**POC仓库:** [CVE-2020-14882](https://github.com/AshrafZaryouh/CVE-2020-14882)  

---

### [CVE-2024-45496](CVE-2024-45496-0xSigSegv0x00_cve-2024-45496.md) 🔴 

**名称:** CVE-2024-45496-Openshift节点权限提升  
**类型:** 权限提升  
**风险:** 高危，可导致节点完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-10-29  
**POC仓库:** [cve-2024-45496](https://github.com/0xSigSegv0x00/cve-2024-45496)  

---

### [CVE-2025-55752](CVE-2025-55752-masahiro331_CVE-2025-55752.md) 🔴 ✅

**名称:** CVE-2025-55752-Apache Tomcat 路径遍历  
**类型:** 路径遍历  
**风险:** 高危，可能导致信息泄露甚至远程代码执行（若PUT方法启用）  
**投毒风险:** 5%  
**发现时间:** 2025-10-29  
**POC仓库:** [CVE-2025-55752](https://github.com/masahiro331/CVE-2025-55752)  

---

### [CVE-2025-61196](CVE-2025-61196-zsamamah_CVE-2025-61196.md) 🔴 ✅

**名称:** CVE-2025-61196-BusinessNext CRMnext-代码执行  
**类型:** 代码执行  
**风险:** 高危，可能导致服务器被控制  
**投毒风险:** 10%  
**发现时间:** 2025-10-29  
**POC仓库:** [CVE-2025-61196](https://github.com/zsamamah/CVE-2025-61196)  

---

### [CVE-2025-59287](CVE-2025-59287-fsanzmoya_wsus_CVE-2025-59287.md) 🔴 ✅

**名称:** CVE-2025-59287 - Windows Server Update Service (WSUS) Remote Code Execution Vulnerability  
**类型:** 反序列化漏洞导致远程代码执行  
**风险:** 高危，允许未经授权的攻击者通过网络执行任意代码。  
**投毒风险:** 0%  
**发现时间:** 2025-10-29  
**POC仓库:** [wsus_CVE-2025-59287](https://github.com/fsanzmoya/wsus_CVE-2025-59287)  

---

### [CVE-2024-48990](CVE-2024-48990-mladicstefan_CVE-2024-48990.md) 🔴 ✅

**名称:** CVE-2024-48990-needrestart-特权提升  
**类型:** 特权提升  
**风险:** 高危，允许本地用户以root权限执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-10-28  
**POC仓库:** [CVE-2024-48990](https://github.com/mladicstefan/CVE-2024-48990)  

---

### [CVE-2024-37032](CVE-2024-37032-stuxbench_vllm-cve-2024-37032.md) 🔴 

**名称:** CVE-2024-37032-Ollama-路径遍历  
**类型:** 路径遍历  
**风险:** 高危，可能导致任意文件读取甚至远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-10-28  
**POC仓库:** [vllm-cve-2024-37032](https://github.com/stuxbench/vllm-cve-2024-37032)  

---

### [CVE-2021-21300](CVE-2021-21300-the-chivalrousZ_cve-2021-21300.md) 🔴 ✅

**名称:** CVE-2021-21300-Git-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行和系统权限获取  
**投毒风险:** 10%  
**发现时间:** 2025-10-28  
**POC仓库:** [cve-2021-21300](https://github.com/the-chivalrousZ/cve-2021-21300)  

---

### [CVE-2025-59287](CVE-2025-59287-esteban11121_WSUS-RCE-Mitigation-59287.md)  ✅

**名称:** CVE-2025-59287-Windows Server Update Service (WSUS) Remote Code Execution  
**类型:** 反序列化漏洞导致远程代码执行  
**风险:** 严重，远程攻击者无需授权即可在受影响的服务器上执行任意代码  
**投毒风险:** 0%  
**发现时间:** 2025-10-28  
**POC仓库:** [WSUS-RCE-Mitigation-59287](https://github.com/esteban11121/WSUS-RCE-Mitigation-59287)  

---

### [CVE-2023-6019](CVE-2023-6019-FireWolfWang_CVE-2023-6019.md) 🔴 ✅

**名称:** CVE-2023-6019 - Ray OS Command Injection  
**类型:** OS Command Injection  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-10-28  
**POC仓库:** [CVE-2023-6019](https://github.com/FireWolfWang/CVE-2023-6019)  

---

### [CVE-2023-6019](CVE-2023-6019-Clydeston_CVE-2023-6019.md) 🔴 ✅

**名称:** CVE-2023-6019 Ray Command Injection in cpu_profile Parameter  
**类型:** 命令注入  
**风险:** 高危，允许远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-10-28  
**POC仓库:** [CVE-2023-6019](https://github.com/Clydeston/CVE-2023-6019)  

---

### [CVE-2023-6019](CVE-2023-6019-Zohaibkhan1472_cve-2023-6019.md) 🔴 ✅

**名称:** CVE-2023-6019-ray-project/ray-命令注入  
**类型:** 命令注入  
**风险:** 高危，允许未经身份验证的远程命令执行  
**投毒风险:** 10%  
**发现时间:** 2025-10-28  
**POC仓库:** [cve-2023-6019](https://github.com/Zohaibkhan1472/cve-2023-6019)  

---

### [CVE-2024-48990](CVE-2024-48990-makuga01_CVE-2024-48990-PoC.md) 🔴 ✅

**名称:** CVE-2024-48990-needrestart-权限提升  
**类型:** 权限提升  
**风险:** 高危，本地用户可以提升到root权限  
**投毒风险:** 0%  
**发现时间:** 2025-10-28  
**POC仓库:** [CVE-2024-48990-PoC](https://github.com/makuga01/CVE-2024-48990-PoC)  

---

### [CVE-2024-48990](CVE-2024-48990-ns989_CVE-2024-48990.md) 🔴 ✅

**名称:** CVE-2024-48990-needrestart-本地权限提升  
**类型:** 本地权限提升  
**风险:** 高危，允许本地用户以root权限执行任意代码  
**投毒风险:** 0%  
**发现时间:** 2025-10-28  
**POC仓库:** [CVE-2024-48990](https://github.com/ns989/CVE-2024-48990)  

---

### [CVE-2024-48990](CVE-2024-48990-felmoltor_CVE-2024-48990.md) 🔴 ✅

**名称:** CVE-2024-48990-needrestart-权限提升  
**类型:** 权限提升  
**风险:** 高危，允许本地用户以root权限执行任意代码  
**投毒风险:** 0%  
**发现时间:** 2025-10-28  
**POC仓库:** [CVE-2024-48990](https://github.com/felmoltor/CVE-2024-48990)  

---

### [CVE-2024-48990](CVE-2024-48990-Cyb3rFr0g_CVE-2024-48990-PoC.md) 🔴 ✅

**名称:** CVE-2024-48990-needrestart-PYTHONPATH提权  
**类型:** 权限提升  
**风险:** 高危，本地攻击者可利用该漏洞以root权限执行任意代码  
**投毒风险:** 0%  
**发现时间:** 2025-10-28  
**POC仓库:** [CVE-2024-48990-PoC](https://github.com/Cyb3rFr0g/CVE-2024-48990-PoC)  

---

### [CVE-2024-48990](CVE-2024-48990-pentestfunctions_CVE-2024-48990-PoC-Testing.md) 🔴 ✅

**名称:** CVE-2024-48990-needrestart-权限提升  
**类型:** 权限提升  
**风险:** 高危，本地攻击者可利用该漏洞以root权限执行任意代码  
**投毒风险:** 0%  
**发现时间:** 2025-10-28  
**POC仓库:** [CVE-2024-48990-PoC-Testing](https://github.com/pentestfunctions/CVE-2024-48990-PoC-Testing)  

---

### [CVE-2024-48990](CVE-2024-48990-ally-petitt_CVE-2024-48990-Exploit.md) 🔴 ✅

**名称:** CVE-2024-48990-needrestart-PYTHONPATH提权  
**类型:** 权限提升  
**风险:** 高危，本地攻击者可以利用该漏洞以root权限执行任意代码  
**投毒风险:** 0%  
**发现时间:** 2025-10-28  
**POC仓库:** [CVE-2024-48990-Exploit](https://github.com/ally-petitt/CVE-2024-48990-Exploit)  

---

### [CVE-2024-48990](CVE-2024-48990-CyberCrowCC_CVE-2024-48990.md) 🔴 ✅

**名称:** CVE-2024-48990 - needrestart 本地提权漏洞  
**类型:** 本地提权  
**风险:** 高危，本地用户可以利用该漏洞以root权限执行任意代码  
**投毒风险:** 1%  
**发现时间:** 2025-10-28  
**POC仓库:** [CVE-2024-48990](https://github.com/CyberCrowCC/CVE-2024-48990)  

---

### [CVE-2024-48990](CVE-2024-48990-NullByte-7w7_CVE-2024-48990.md) 🔴 ✅

**名称:** CVE-2024-48990-needrestart-权限提升  
**类型:** 权限提升  
**风险:** 高危，本地用户可提升至root权限  
**投毒风险:** 5%  
**发现时间:** 2025-10-28  
**POC仓库:** [CVE-2024-48990](https://github.com/NullByte-7w7/CVE-2024-48990)  

---

### [CVE-2024-48990](CVE-2024-48990-ten-ops_CVE-2024-48990_needrestart.md) 🔴 

**名称:** CVE-2024-48990-needrestart-权限提升  
**类型:** 权限提升  
**风险:** 高危，本地用户可提升为root权限  
**投毒风险:** 0%  
**发现时间:** 2025-10-28  
**POC仓库:** [CVE-2024-48990_needrestart](https://github.com/ten-ops/CVE-2024-48990_needrestart)  

---

### [CVE-2024-48990](CVE-2024-48990-Serner77_CVE-2024-48990-Automatic-Exploit.md) 🔴 ✅

**名称:** CVE-2024-48990-needrestart-权限提升  
**类型:** 权限提升  
**风险:** 高危，允许本地用户以root权限执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-10-28  
**POC仓库:** [CVE-2024-48990-Automatic-Exploit](https://github.com/Serner77/CVE-2024-48990-Automatic-Exploit)  

---

### [CVE-2025-59287](CVE-2025-59287-FurkanKAYAPINAR_CVE-2025-59287.md)  ✅

**名称:** CVE-2025-59287 - Windows Server Update Service (WSUS) Remote Code Execution  
**类型:** 远程代码执行  
**风险:** 严重，允许未经授权的攻击者通过网络执行代码  
**投毒风险:** 10%  
**发现时间:** 2025-10-28  
**POC仓库:** [CVE-2025-59287](https://github.com/FurkanKAYAPINAR/CVE-2025-59287)  

---

### [CVE-2025-55752](CVE-2025-55752-TAM-K592_CVE-2025-55752-.md) 🔴 ✅

**名称:** CVE-2025-55752-Apache Tomcat 目录遍历及潜在RCE  
**类型:** 目录遍历/远程代码执行  
**风险:** 高危，可能导致敏感信息泄露和远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-10-28  
**POC仓库:** [CVE-2025-55752-](https://github.com/TAM-K592/CVE-2025-55752-)  

---

### [CVE-2018-9995](CVE-2018-9995-gwolfs_CVE-2018-9995-ModifiedByGwolfs.md) 🔴 ✅

**名称:** CVE-2018-9995 - TBK DVR认证绕过  
**类型:** 认证绕过  
**风险:** 高危，可能导致未经授权的访问和控制  
**投毒风险:** 10%  
**发现时间:** 2025-10-28  
**POC仓库:** [CVE-2018-9995-ModifiedByGwolfs](https://github.com/gwolfs/CVE-2018-9995-ModifiedByGwolfs)  

---

### [CVE-2018-9995](CVE-2018-9995-shacojx_cve-2018-9995.md) 🔴 ✅

**名称:** CVE-2018-9995 - TBK DVR 认证绕过  
**类型:** 认证绕过  
**风险:** 高危，可能导致未授权访问和敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-10-28  
**POC仓库:** [cve-2018-9995](https://github.com/shacojx/cve-2018-9995)  

---

### [CVE-2018-9995](CVE-2018-9995-Cyb0r9_DVR-Exploiter.md) 🔴 ✅

**名称:** CVE-2018-9995 - TBK DVR Authentication Bypass  
**类型:** 身份验证绕过  
**风险:** 高危，可能导致未授权访问、视频泄露和设备控制  
**投毒风险:** 0%  
**发现时间:** 2025-10-28  
**POC仓库:** [DVR-Exploiter](https://github.com/Cyb0r9/DVR-Exploiter)  

---

### [CVE-2018-9995](CVE-2018-9995-ezelf_CVE-2018-9995_dvr_credentials.md) 🔴 ✅

**名称:** CVE-2018-9995 - TBK DVR设备认证绕过  
**类型:** 认证绕过  
**风险:** 高危，可能导致未经授权的访问和控制  
**投毒风险:** 0%  
**发现时间:** 2025-10-28  
**POC仓库:** [CVE-2018-9995_dvr_credentials](https://github.com/ezelf/CVE-2018-9995_dvr_credentials)  

---

### [CVE-2025-55854](CVE-2025-55854-PushkarAyengar_CVE-2025-55854-PoC.md) 🔴 ✅

**名称:** CVE-2025-55854 - FreelanceHub - Stored XSS  
**类型:** Stored Cross-Site Scripting (XSS)  
**风险:** 高危，可能导致会话劫持、凭据窃取、数据泄露、恶意软件分发、网络钓鱼攻击和帐户接管  
**投毒风险:** 1%  
**发现时间:** 2025-10-28  
**POC仓库:** [CVE-2025-55854-PoC](https://github.com/PushkarAyengar/CVE-2025-55854-PoC)  

---

### [CVE-2018-9995](CVE-2018-9995-Huangkey_CVE-2018-9995_check.md) 🔴 ✅

**名称:** CVE-2018-9995 - TBK DVR 身份验证绕过  
**类型:** 身份验证绕过  
**风险:** 高危，可能导致未授权访问DVR设备及其视频流  
**投毒风险:** 10%  
**发现时间:** 2025-10-28  
**POC仓库:** [CVE-2018-9995_check](https://github.com/Huangkey/CVE-2018-9995_check)  

---

### [CVE-2018-9995](CVE-2018-9995-zzh217_CVE-2018-9995_Batch_scanning_exp.md) 🔴 ✅

**名称:** CVE-2018-9995 - TBK DVR 认证绕过  
**类型:** 认证绕过  
**风险:** 高危，可能导致未授权访问和控制设备  
**投毒风险:** 5%  
**发现时间:** 2025-10-28  
**POC仓库:** [CVE-2018-9995_Batch_scanning_exp](https://github.com/zzh217/CVE-2018-9995_Batch_scanning_exp)  

---

### [CVE-2018-9995](CVE-2018-9995-codeholic2k18_CVE-2018-9995.md) 🔴 ✅

**名称:** CVE-2018-9995 - TBK DVR身份验证绕过  
**类型:** 身份验证绕过  
**风险:** 高危，可能导致未授权访问，信息泄露，远程控制  
**投毒风险:** 0%  
**发现时间:** 2025-10-28  
**POC仓库:** [CVE-2018-9995](https://github.com/codeholic2k18/CVE-2018-9995)  

---

### [CVE-2018-9995](CVE-2018-9995-TateYdq_CVE-2018-9995-ModifiedByGwolfs.md) 🔴 ✅

**名称:** CVE-2018-9995 - TBK DVR身份验证绕过  
**类型:** 身份验证绕过  
**风险:** 高危，可能导致未授权访问DVR设备及其视频流  
**投毒风险:** 0%  
**发现时间:** 2025-10-28  
**POC仓库:** [CVE-2018-9995-ModifiedByGwolfs](https://github.com/TateYdq/CVE-2018-9995-ModifiedByGwolfs)  

---

### [CVE-2018-9995](CVE-2018-9995-ABIZCHI_CVE-2018-9995_dvr_credentials.md) 🔴 ✅

**名称:** CVE-2018-9995 - TBK DVR 身份验证绕过  
**类型:** 身份验证绕过  
**风险:** 高危，可能导致未授权访问和控制DVR设备  
**投毒风险:** 10%  
**发现时间:** 2025-10-28  
**POC仓库:** [CVE-2018-9995_dvr_credentials](https://github.com/ABIZCHI/CVE-2018-9995_dvr_credentials)  

---

### [CVE-2018-9995](CVE-2018-9995-MrAli-Code_CVE-2018-9995_dvr_credentials.md) 🔴 ✅

**名称:** CVE-2018-9995 - TBK DVR身份验证绕过  
**类型:** 身份验证绕过  
**风险:** 高危，可能导致未授权访问、数据泄露和远程控制  
**投毒风险:** 0%  
**发现时间:** 2025-10-28  
**POC仓库:** [CVE-2018-9995_dvr_credentials](https://github.com/MrAli-Code/CVE-2018-9995_dvr_credentials)  

---

### [CVE-2018-9995](CVE-2018-9995-likaifeng0_CVE-2018-9995_dvr_credentials-dev_tool.md) 🔴 ✅

**名称:** CVE-2018-9995 - TBK DVR及相关品牌DVR认证绕过  
**类型:** 认证绕过  
**风险:** 高危，可能导致未授权访问、信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-10-28  
**POC仓库:** [CVE-2018-9995_dvr_credentials-dev_tool](https://github.com/likaifeng0/CVE-2018-9995_dvr_credentials-dev_tool)  

---

### [CVE-2018-9995](CVE-2018-9995-b510_CVE-2018-9995-POC.md) 🔴 ✅

**名称:** CVE-2018-9995 - TBK DVR 认证绕过  
**类型:** 认证绕过  
**风险:** 高危，可能导致未授权访问和数据泄露  
**投毒风险:** 0%  
**发现时间:** 2025-10-28  
**POC仓库:** [CVE-2018-9995-POC](https://github.com/b510/CVE-2018-9995-POC)  

---

### [CVE-2018-9995](CVE-2018-9995-awesome-consumer-iot_HTC.md) 🔴 ✅

**名称:** CVE-2018-9995-TBK DVR-Authentication Bypass  
**类型:** 身份验证绕过  
**风险:** 高危，可能导致未授权访问DVR设备，泄露视频数据，甚至控制设备。  
**投毒风险:** 10%  
**发现时间:** 2025-10-28  
**POC仓库:** [HTC](https://github.com/awesome-consumer-iot/HTC)  

---

### [CVE-2018-9995](CVE-2018-9995-Saeed22487_CVE-2018-9995.md) 🔴 ✅

**名称:** CVE-2018-9995 - TBK DVR认证绕过  
**类型:** 认证绕过  
**风险:** 高危，允许未授权访问敏感信息和控制DVR设备  
**投毒风险:** 10%  
**发现时间:** 2025-10-28  
**POC仓库:** [CVE-2018-9995](https://github.com/Saeed22487/CVE-2018-9995)  

---

### [CVE-2018-9995](CVE-2018-9995-kienquoc102_CVE-2018-9995-2.md) 🔴 ✅

**名称:** CVE-2018-9995 - TBK DVR 身份验证绕过  
**类型:** 身份验证绕过  
**风险:** 高危，允许未经授权的远程访问  
**投毒风险:** 10%  
**发现时间:** 2025-10-28  
**POC仓库:** [CVE-2018-9995-2](https://github.com/kienquoc102/CVE-2018-9995-2)  

---

### [CVE-2018-9995](CVE-2018-9995-dearpan_cve-2018-9995.md) 🔴 ✅

**名称:** CVE-2018-9995 - TBK DVR 认证绕过  
**类型:** 认证绕过  
**风险:** 高危，允许未授权访问DVR控制面板，获取敏感信息如用户名和密码  
**投毒风险:** 0%  
**发现时间:** 2025-10-28  
**POC仓库:** [cve-2018-9995](https://github.com/dearpan/cve-2018-9995)  

---

### [CVE-2018-9995](CVE-2018-9995-LeQuocKhanh2K_Tool_Exploit_Password_Camera_CVE-2018-9995.md) 🔴 ✅

**名称:** CVE-2018-9995 - TBK DVR 认证绕过  
**类型:** 认证绕过  
**风险:** 高危，可能导致未授权访问和敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-10-28  
**POC仓库:** [Tool_Exploit_Password_Camera_CVE-2018-9995](https://github.com/LeQuocKhanh2K/Tool_Exploit_Password_Camera_CVE-2018-9995)  

---

### [CVE-2018-9995](CVE-2018-9995-wmasday_HTC.md) 🔴 ✅

**名称:** CVE-2018-9995-TBK DVR身份认证绕过  
**类型:** 身份认证绕过  
**风险:** 高危，可能导致未授权访问视频监控信息  
**投毒风险:** 0%  
**发现时间:** 2025-10-28  
**POC仓库:** [HTC](https://github.com/wmasday/HTC)  

---

### [CVE-2018-9995](CVE-2018-9995-K3ysTr0K3R_CVE-2018-9995-EXPLOIT.md) 🔴 ✅

**名称:** CVE-2018-9995 - TBK DVR 身份验证绕过  
**类型:** 身份验证绕过  
**风险:** 高危，可能导致未授权访问 DVR 设备和视频流  
**投毒风险:** 5%  
**发现时间:** 2025-10-28  
**POC仓库:** [CVE-2018-9995-EXPLOIT](https://github.com/K3ysTr0K3R/CVE-2018-9995-EXPLOIT)  

---

### [CVE-2018-9995](CVE-2018-9995-arminarab1999_CVE-2018-9995.md) 🔴 ✅

**名称:** CVE-2018-9995 - TBK DVR Authentication Bypass  
**类型:** 身份验证绕过  
**风险:** 高危，未经授权的访问，可能导致敏感信息泄露、设备控制等  
**投毒风险:** 10%  
**发现时间:** 2025-10-28  
**POC仓库:** [CVE-2018-9995](https://github.com/arminarab1999/CVE-2018-9995)  

---

### [CVE-2018-9995](CVE-2018-9995-X3RX3SSec_DVR_Sploit.md) 🔴 ✅

**名称:** CVE-2018-9995 - TBK DVR 身份验证绕过  
**类型:** 身份验证绕过  
**风险:** 高危，可能导致未授权访问设备及视频流  
**投毒风险:** 0%  
**发现时间:** 2025-10-28  
**POC仓库:** [DVR_Sploit](https://github.com/X3RX3SSec/DVR_Sploit)  

---

### [CVE-2018-9995](CVE-2018-9995-dego905_Cam.md) 🔴 ✅

**名称:** CVE-2018-9995-TBK DVR身份认证绕过  
**类型:** 身份认证绕过  
**风险:** 高危，可能导致未经授权的访问和控制  
**投毒风险:** 0%  
**发现时间:** 2025-10-28  
**POC仓库:** [Cam](https://github.com/dego905/Cam)  

---

### [CVE-2018-9995](CVE-2018-9995-A-Alabdoo_CVE-DVr.md) 🔴 ✅

**名称:** CVE-2018-9995 - TBK DVR身份验证绕过  
**类型:** 身份验证绕过  
**风险:** 高危，可能导致未授权访问设备及其视频流  
**投毒风险:** 0%  
**发现时间:** 2025-10-28  
**POC仓库:** [CVE-DVr](https://github.com/A-Alabdoo/CVE-DVr)  

---

### [CVE-2018-9995](CVE-2018-9995-batmoshka55_CVE-2018-9995_dvr_credentials.md) 🔴 ✅

**名称:** CVE-2018-9995 - TBK DVR 身份验证绕过  
**类型:** 身份验证绕过  
**风险:** 高危，可能允许未经授权的远程访问和控制设备  
**投毒风险:** 0%  
**发现时间:** 2025-10-28  
**POC仓库:** [CVE-2018-9995_dvr_credentials](https://github.com/batmoshka55/CVE-2018-9995_dvr_credentials)  

---

### [CVE-2018-9995](CVE-2018-9995-its-anya_DVR_Credential_Scanner.md) 🔴 ✅

**名称:** CVE-2018-9995 - TBK DVR 身份验证绕过  
**类型:** 身份验证绕过  
**风险:** 高危，允许未经身份验证的远程攻击者访问设备  
**投毒风险:** 5%  
**发现时间:** 2025-10-28  
**POC仓库:** [DVR_Credential_Scanner](https://github.com/its-anya/DVR_Credential_Scanner)  

---

### [CVE-2018-9995](CVE-2018-9995-ST0PL_DVRFaultNET.md) 🔴 ✅

**名称:** CVE-2018-9995 - TBK DVR Authentication Bypass  
**类型:** 身份验证绕过  
**风险:** 高危，可能导致未经授权的访问、数据泄露以及远程控制  
**投毒风险:** 10%  
**发现时间:** 2025-10-28  
**POC仓库:** [DVRFaultNET](https://github.com/ST0PL/DVRFaultNET)  

---

### [CVE-2018-9995](CVE-2018-9995-jameseyes_DVRC.md) 🔴 ✅

**名称:** CVE-2018-9995 - TBK DVR 认证绕过  
**类型:** 认证绕过  
**风险:** 高危，可未经授权访问DVR设备  
**投毒风险:** 0%  
**发现时间:** 2025-10-28  
**POC仓库:** [DVRC](https://github.com/jameseyes/DVRC)  

---

### [CVE-2018-9995](CVE-2018-9995-0xDamian_CVE-2018-9995-rs.md) 🔴 ✅

**名称:** CVE-2018-9995-TBK DVR系列设备-认证绕过  
**类型:** 认证绕过  
**风险:** 高危，可能导致未授权访问、数据泄露和远程控制  
**投毒风险:** 2%  
**发现时间:** 2025-10-28  
**POC仓库:** [CVE-2018-9995-rs](https://github.com/0xDamian/CVE-2018-9995-rs)  

---

### [CVE-2021-42013](CVE-2021-42013-FakhriCRD_Apache-CVE-2021-42013-RCE-Exploit.md) 🔴 ✅

**名称:** CVE-2021-42013 - Apache HTTP Server RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致完全系统入侵和控制  
**投毒风险:** 10%  
**发现时间:** 2025-10-28  
**POC仓库:** [Apache-CVE-2021-42013-RCE-Exploit](https://github.com/FakhriCRD/Apache-CVE-2021-42013-RCE-Exploit)  

---

### [CVE-2025-59230](CVE-2025-59230-stalker110119_CVE-2025-59230.md) 🔴 ✅

**名称:** CVE-2025-59230 - Windows Remote Access Connection Manager Elevation of Privilege Vulnerability  
**类型:** 权限提升  
**风险:** 高危，本地权限提升至SYSTEM  
**投毒风险:** 10%  
**发现时间:** 2025-10-28  
**POC仓库:** [CVE-2025-59230](https://github.com/stalker110119/CVE-2025-59230)  

---

### [CVE-2025-59230](CVE-2025-59230-moegameka_CVE-2025-59230-LPE.md) 🔴 ✅

**名称:** CVE-2025-59230 - Windows Remote Access Connection Manager LPE  
**类型:** 本地权限提升 (LPE)  
**风险:** 高危，攻击者可从低权限用户提升至SYSTEM权限  
**投毒风险:** 20%  
**发现时间:** 2025-10-28  
**POC仓库:** [CVE-2025-59230-LPE](https://github.com/moegameka/CVE-2025-59230-LPE)  

---

### [CVE-2025-60595](CVE-2025-60595-Clicksafeae_CVE-2025-60595.md) 🔴 ✅

**名称:** CVE-2025-60595-SPH Engineering UgCS-Arbitrary Code Execution  
**类型:** Arbitrary Code Execution  
**风险:** 高危，可能导致远程代码执行和系统控制  
**投毒风险:** 5%  
**发现时间:** 2025-10-28  
**POC仓库:** [CVE-2025-60595](https://github.com/Clicksafeae/CVE-2025-60595)  

---

### [CVE-2025-59287](CVE-2025-59287-mrk336_Breaking-the-Update-Chain-Inside-CVE-2025-59287-and-the-WSUS-RCE-Threat.md) 🔴 ✅

**名称:** CVE-2025-59287 - Windows Server Update Service (WSUS) 远程代码执行漏洞  
**类型:** 反序列化漏洞导致远程代码执行  
**风险:** 高危，未经授权的攻击者可以通过网络执行任意代码。  
**投毒风险:** 10%  
**发现时间:** 2025-10-28  
**POC仓库:** [Breaking-the-Update-Chain-Inside-CVE-2025-59287-and-the-WSUS-RCE-Threat](https://github.com/mrk336/Breaking-the-Update-Chain-Inside-CVE-2025-59287-and-the-WSUS-RCE-Threat)  

---

### [CVE-2025-59287](CVE-2025-59287-AdityaBhatt3010_CVE-2025-59287-When-your-patch-server-becomes-the-attack-vector.md) 🔴 ✅

**名称:** CVE-2025-59287-Windows Server Update Service (WSUS) Remote Code Execution Vulnerability  
**类型:** 反序列化漏洞  
**风险:** 高危，可导致远程代码执行，控制受影响的服务器  
**投毒风险:** 10%  
**发现时间:** 2025-10-28  
**POC仓库:** [CVE-2025-59287-When-your-patch-server-becomes-the-attack-vector](https://github.com/AdityaBhatt3010/CVE-2025-59287-When-your-patch-server-becomes-the-attack-vector)  

---

### [CVE-2023-26360](CVE-2023-26360-jakabakos_CVE-2023-26360-adobe-coldfusion-rce-exploit.md) 🔴 ✅

**名称:** CVE-2023-26360-Adobe ColdFusion-不当访问控制/反序列化RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-10-28  
**POC仓库:** [CVE-2023-26360-adobe-coldfusion-rce-exploit](https://github.com/jakabakos/CVE-2023-26360-adobe-coldfusion-rce-exploit)  

---

### [CVE-2023-26360](CVE-2023-26360-yosef0x01_CVE-2023-26360.md) 🔴 ✅

**名称:** CVE-2023-26360 Adobe ColdFusion Improper Access Control Arbitrary code execution  
**类型:** Improper Access Control  
**风险:** 高危，可能导致任意代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-10-28  
**POC仓库:** [CVE-2023-26360](https://github.com/yosef0x01/CVE-2023-26360)  

---

### [CVE-2023-26360](CVE-2023-26360-CuriousLearnerDev_ColdFusion_EXp.md) 🔴 ✅

**名称:** CVE-2023-26360 - Adobe ColdFusion Improper Access Control Arbitrary code execution  
**类型:** 代码执行  
**风险:** 高危，允许未经身份验证的远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-10-28  
**POC仓库:** [ColdFusion_EXp](https://github.com/CuriousLearnerDev/ColdFusion_EXp)  

---

### [CVE-2023-26360](CVE-2023-26360-issamjr_CVE-2023-26360.md) 🔴 ✅

**名称:** CVE-2023-26360-Adobe ColdFusion 任意代码执行  
**类型:** 任意代码执行  
**风险:** 高危，允许未经身份验证的攻击者执行任意代码  
**投毒风险:** 5%  
**发现时间:** 2025-10-28  
**POC仓库:** [CVE-2023-26360](https://github.com/issamjr/CVE-2023-26360)  

---

### [CVE-2023-26360](CVE-2023-26360-H3rm1tR3b0rn_CVE-2023-26360-RCE.md) 🔴 ✅

**名称:** CVE-2023-26360  
**类型:** 不当访问控制导致任意代码执行  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-10-28  
**POC仓库:** [CVE-2023-26360-RCE](https://github.com/H3rm1tR3b0rn/CVE-2023-26360-RCE)  

---

### [CVE-2025-61882](CVE-2025-61882-GhoStZA-debug_CVE-2025-61882.md) 🔴 ✅

**名称:** CVE-2025-61882-Oracle Concurrent Processing-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可完全控制受影响的系统  
**投毒风险:** 10%  
**发现时间:** 2025-10-28  
**POC仓库:** [CVE-2025-61882](https://github.com/GhoStZA-debug/CVE-2025-61882)  

---

### [CVE-2025-29927](CVE-2025-29927-lucaschanzx_CVE-2025-29927-PoC.md) 🔴 ✅

**名称:** CVE-2025-29927-Next.js-Authorization Bypass  
**类型:** 权限绕过  
**风险:** 高危，可能导致未授权访问敏感数据或执行未授权操作  
**投毒风险:** 0%  
**发现时间:** 2025-10-28  
**POC仓库:** [CVE-2025-29927-PoC](https://github.com/lucaschanzx/CVE-2025-29927-PoC)  

---

### [CVE-2020-27955](CVE-2020-27955-ExploitBox_git-lfs-RCE-exploit-CVE-2020-27955-Go.md) 🔴 ✅

**名称:** CVE-2020-27955 Git LFS Remote Code Execution  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-10-28  
**POC仓库:** [git-lfs-RCE-exploit-CVE-2020-27955-Go](https://github.com/ExploitBox/git-lfs-RCE-exploit-CVE-2020-27955-Go)  

---

### [CVE-2020-27955](CVE-2020-27955-yhsung_cve-2020-27955-poc.md) 🔴 ✅

**名称:** CVE-2020-27955-Git LFS-RCE  
**类型:** RCE  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-10-28  
**POC仓库:** [cve-2020-27955-poc](https://github.com/yhsung/cve-2020-27955-poc)  

---

### [CVE-2020-27955](CVE-2020-27955-r00t4dm_CVE-2020-27955.md) 🔴 ✅

**名称:** CVE-2020-27955 Git LFS RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可导致服务器被完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-10-28  
**POC仓库:** [CVE-2020-27955](https://github.com/r00t4dm/CVE-2020-27955)  

---

### [CVE-2020-27955](CVE-2020-27955-TheTh1nk3r_cve-2020-27955.md) 🔴 ✅

**名称:** CVE-2020-27955 - Git LFS Remote Code Execution  
**类型:** Remote Code Execution (RCE)  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-10-28  
**POC仓库:** [cve-2020-27955](https://github.com/TheTh1nk3r/cve-2020-27955)  

---

### [CVE-2020-27955](CVE-2020-27955-ExploitBox_git-lfs-RCE-exploit-CVE-2020-27955.md) 🔴 ✅

**名称:** CVE-2020-27955-Git LFS-RCE  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-10-28  
**POC仓库:** [git-lfs-RCE-exploit-CVE-2020-27955](https://github.com/ExploitBox/git-lfs-RCE-exploit-CVE-2020-27955)  

---

### [CVE-2020-27955](CVE-2020-27955-NeoDarwin_CVE-2020-27955.md) 🔴 ✅

**名称:** CVE-2020-27955 - Git LFS Remote Code Execution  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，允许攻击者在受害者机器上执行任意代码  
**投毒风险:** 0%  
**发现时间:** 2025-10-28  
**POC仓库:** [CVE-2020-27955](https://github.com/NeoDarwin/CVE-2020-27955)  

---

### [CVE-2020-27955](CVE-2020-27955-DeeLMind_CVE-2020-27955-LFS.md) 🔴 ✅

**名称:** CVE-2020-27955-Git LFS-RCE  
**类型:** 远程代码执行  
**风险:** 高危，允许攻击者在目标机器上执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-10-28  
**POC仓库:** [CVE-2020-27955-LFS](https://github.com/DeeLMind/CVE-2020-27955-LFS)  

---

### [CVE-2020-27955](CVE-2020-27955-HK69s_CVE-2020-27955.md) 🔴 ✅

**名称:** CVE-2020-27955-Git LFS-RCE  
**类型:** 远程代码执行  
**风险:** 高危，允许远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-10-28  
**POC仓库:** [CVE-2020-27955](https://github.com/HK69s/CVE-2020-27955)  

---

### [CVE-2020-27955](CVE-2020-27955-IanSmith123_CVE-2020-27955.md) 🔴 ✅

**名称:** CVE-2020-27955 Git LFS RCE  
**类型:** 远程代码执行  
**风险:** 高危，可导致服务器被完全控制  
**投毒风险:** 80%  
**发现时间:** 2025-10-28  
**POC仓库:** [CVE-2020-27955](https://github.com/IanSmith123/CVE-2020-27955)  

---

### [CVE-2020-27955](CVE-2020-27955-Arnoldqqq_CVE-2020-27955.md) 🔴 ✅

**名称:** CVE-2020-27955-Git LFS-RCE  
**类型:** 远程代码执行  
**风险:** 高危，允许攻击者在目标系统上执行任意代码  
**投毒风险:** 0%  
**发现时间:** 2025-10-28  
**POC仓库:** [CVE-2020-27955](https://github.com/Arnoldqqq/CVE-2020-27955)  

---

### [CVE-2020-27955](CVE-2020-27955-nob0dy-3389_CVE-2020-27955.md) 🔴 ✅

**名称:** CVE-2020-27955-Git LFS-RCE  
**类型:** 远程代码执行  
**风险:** 高危，可能导致完全控制目标系统  
**投毒风险:** 10%  
**发现时间:** 2025-10-28  
**POC仓库:** [CVE-2020-27955](https://github.com/nob0dy-3389/CVE-2020-27955)  

---

### [CVE-2020-27955](CVE-2020-27955-Marsable_CVE-2020-27955-LFS.md) 🔴 ✅

**名称:** CVE-2020-27955-Git LFS-RCE  
**类型:** 远程代码执行  
**风险:** 高危，允许远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-10-28  
**POC仓库:** [CVE-2020-27955-LFS](https://github.com/Marsable/CVE-2020-27955-LFS)  

---

### [CVE-2020-27955](CVE-2020-27955-FrostsaberX_CVE-2020-27955.md) 🔴 ✅

**名称:** CVE-2020-27955 Git LFS Remote Code Execution  
**类型:** Remote Code Execution  
**风险:** 高危，允许远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-10-28  
**POC仓库:** [CVE-2020-27955](https://github.com/FrostsaberX/CVE-2020-27955)  

---

### [CVE-2020-27955](CVE-2020-27955-whitetea2424_CVE-2020-27955-LFS-main.md) 🔴 ✅

**名称:** CVE-2020-27955 Git LFS RCE  
**类型:** 远程代码执行  
**风险:** 高危，可导致服务器被完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-10-28  
**POC仓库:** [CVE-2020-27955-LFS-main](https://github.com/whitetea2424/CVE-2020-27955-LFS-main)  

---

### [CVE-2020-27955](CVE-2020-27955-userxfan_cve-2020-27955.md) 🔴 ✅

**名称:** CVE-2020-27955-Git LFS Remote Code Execution  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-10-28  
**POC仓库:** [cve-2020-27955](https://github.com/userxfan/cve-2020-27955)  

---

### [CVE-2020-27955](CVE-2020-27955-z50913_CVE-2020-27955.md) 🔴 ✅

**名称:** CVE-2020-27955 Git LFS Remote Code Execution  
**类型:** Remote Code Execution  
**风险:** 高危，可完全控制目标系统  
**投毒风险:** 10%  
**发现时间:** 2025-10-28  
**POC仓库:** [CVE-2020-27955](https://github.com/z50913/CVE-2020-27955)  

---

### [CVE-2020-27955](CVE-2020-27955-Kimorea_CVE-2020-27955-LFS.md) 🔴 ✅

**名称:** CVE-2020-27955-Git LFS-RCE  
**类型:** 远程代码执行  
**风险:** 高危，可导致服务器被完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-10-28  
**POC仓库:** [CVE-2020-27955-LFS](https://github.com/Kimorea/CVE-2020-27955-LFS)  

---

### [CVE-2020-27955](CVE-2020-27955-the-chivalrousZ_cve-2020-27955.md) 🔴 ✅

**名称:** CVE-2020-27955 Git LFS Remote Code Execution  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可导致服务器被完全控制  
**投毒风险:** 1%  
**发现时间:** 2025-10-28  
**POC仓库:** [cve-2020-27955](https://github.com/the-chivalrousZ/cve-2020-27955)  

---

### [CVE-2025-29927](CVE-2025-29927-NS-Projects-Unina_CTF_CVE_DSP_1.md) 🔴 ✅

**名称:** CVE-2025-29927-Next.js Middleware Authorization Bypass  
**类型:** 授权绕过  
**风险:** 高危，可能导致未授权访问和数据泄露  
**投毒风险:** 1%  
**发现时间:** 2025-10-27  
**POC仓库:** [CTF_CVE_DSP_1](https://github.com/NS-Projects-Unina/CTF_CVE_DSP_1)  

---

### [CVE-2024-37032](CVE-2024-37032-Bi0x_CVE-2024-37032.md) 🔴 ✅

**名称:** CVE-2024-37032-Ollama-路径遍历  
**类型:** 路径遍历  
**风险:** 高危，可能导致任意文件读取和写入，甚至远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-10-27  
**POC仓库:** [CVE-2024-37032](https://github.com/Bi0x/CVE-2024-37032)  

---

### [CVE-2024-37032](CVE-2024-37032-ahboon_CVE-2024-37032-scanner.md) 🔴 ✅

**名称:** CVE-2024-37032 - Ollama Path Traversal  
**类型:** 路径遍历/远程代码执行 (RCE)  
**风险:** 高危，可能导致文件读取、写入甚至远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-10-27  
**POC仓库:** [CVE-2024-37032-scanner](https://github.com/ahboon/CVE-2024-37032-scanner)  

---

### [CVE-2024-37032](CVE-2024-37032-pankass_CVE-2024-37032_CVE-2024-45436.md) 🔴 ✅

**名称:** CVE-2024-37032 Ollama 路径遍历导致RCE  
**类型:** 路径遍历/远程代码执行  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-10-27  
**POC仓库:** [CVE-2024-37032_CVE-2024-45436](https://github.com/pankass/CVE-2024-37032_CVE-2024-45436)  

---

### [CVE-2025-46817](CVE-2025-46817-slayerkkkk_CVE-2025-46817-PoC.md) 🔴 ✅

**名称:** CVE-2025-46817 Redis Integer Overflow RCE  
**类型:** Integer Overflow  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-10-27  
**POC仓库:** [CVE-2025-46817-PoC](https://github.com/slayerkkkk/CVE-2025-46817-PoC)  

---

### [CVE-2025-59287](CVE-2025-59287-mubix_Find-WSUS.md) 🔴 ✅

**名称:** CVE-2025-59287-Windows Server Update Service (WSUS) Remote Code Execution  
**类型:** 反序列化漏洞  
**风险:** 高危，允许远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-10-27  
**POC仓库:** [Find-WSUS](https://github.com/mubix/Find-WSUS)  

---

### [CVE-2021-22204](CVE-2021-22204-Asaad27_CVE-2021-22204-RSE.md) 🔴 ✅

**名称:** CVE-2021-22204-ExifTool-DjVu代码执行  
**类型:** 代码执行  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-10-27  
**POC仓库:** [CVE-2021-22204-RSE](https://github.com/Asaad27/CVE-2021-22204-RSE)  

---

### [CVE-2025-61156](CVE-2025-61156-D7EAD_CVE-2025-61156.md) 🔴 ✅

**名称:** CVE-2025-61156 - ThreatFire System Monitor Arbitrary Process Termination  
**类型:** 权限提升/拒绝服务  
**风险:** 高危，可绕过EDR，导致拒绝服务  
**投毒风险:** 0%  
**发现时间:** 2025-10-27  
**POC仓库:** [CVE-2025-61156](https://github.com/D7EAD/CVE-2025-61156)  

---

### [CVE-2025-61882](CVE-2025-61882-AshrafZaryouh_CVE-2025-61882-Executive-Summary.md) 🔴 ✅

**名称:** CVE-2025-61882-Oracle Concurrent Processing-RCE  
**类型:** 远程代码执行(RCE)  
**风险:** 高危，允许未经身份验证的攻击者完全控制系统  
**投毒风险:** 10%  
**发现时间:** 2025-10-27  
**POC仓库:** [CVE-2025-61882-Executive-Summary](https://github.com/AshrafZaryouh/CVE-2025-61882-Executive-Summary)  

---

### [CVE-2021-44142](CVE-2021-44142-hrsman_Samba-CVE-2021-44142.md) 🔴 ✅

**名称:** CVE-2021-44142-Samba-vfs_fruit模块堆溢出  
**类型:** 堆溢出  
**风险:** 高危，允许远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-10-27  
**POC仓库:** [Samba-CVE-2021-44142](https://github.com/hrsman/Samba-CVE-2021-44142)  

---

### [CVE-2021-44142](CVE-2021-44142-horizon3ai_CVE-2021-44142.md) 🔴 ✅

**名称:** CVE-2021-44142-Samba-vfs_fruit-堆溢出  
**类型:** 堆溢出  
**风险:** 高危，远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-10-27  
**POC仓库:** [CVE-2021-44142](https://github.com/horizon3ai/CVE-2021-44142)  

---

### [CVE-2021-44142](CVE-2021-44142-gudyrmik_CVE-2021-44142.md) 🔴 ✅

**名称:** CVE-2021-44142-Samba-vfs_fruit-堆溢出  
**类型:** 堆溢出（Out-of-bounds Read/Write）  
**风险:** 高危，允许远程攻击者以smbd（通常是root）权限执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-10-27  
**POC仓库:** [CVE-2021-44142](https://github.com/gudyrmik/CVE-2021-44142)  

---

### [CVE-2021-44142](CVE-2021-44142-WinDyAlphA_CVE-2021-44142-vulnerable-lab.md) 🔴 ✅

**名称:** CVE-2021-44142-Samba vfs_fruit 模块堆溢出  
**类型:** 堆溢出（Out-of-bounds Read/Write）  
**风险:** 高危，远程攻击者可能以 smbd 进程（通常为 root 权限）执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-10-27  
**POC仓库:** [CVE-2021-44142-vulnerable-lab](https://github.com/WinDyAlphA/CVE-2021-44142-vulnerable-lab)  

---

### [CVE-2021-22204](CVE-2021-22204-se162xg_CVE-2021-22204.md) 🟡 ✅

**名称:** CVE-2021-22204-ExifTool-DjVu代码注入  
**类型:** 代码注入  
**风险:** 中危，可导致本地代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-10-27  
**POC仓库:** [CVE-2021-22204](https://github.com/se162xg/CVE-2021-22204)  

---

### [CVE-2021-22204](CVE-2021-22204-convisolabs_CVE-2021-22204-exiftool.md) 🔴 ✅

**名称:** CVE-2021-22204-ExifTool-代码执行  
**类型:** 代码执行  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-10-27  
**POC仓库:** [CVE-2021-22204-exiftool](https://github.com/convisolabs/CVE-2021-22204-exiftool)  

---

### [CVE-2021-22204](CVE-2021-22204-bilkoh_POC-CVE-2021-22204.md) 🟡 ✅

**名称:** CVE-2021-22204-ExifTool-DjVu-ANT-Perl注入  
**类型:** 代码注入  
**风险:** 中危，可能导致敏感信息泄露或执行恶意代码  
**投毒风险:** 0%  
**发现时间:** 2025-10-27  
**POC仓库:** [POC-CVE-2021-22204](https://github.com/bilkoh/POC-CVE-2021-22204)  

---

### [CVE-2021-22204](CVE-2021-22204-PenTestical_CVE-2021-22204.md) 🔴 ✅

**名称:** CVE-2021-22204 - ExifTool DjVu Arbitrary Code Execution  
**类型:** 代码注入  
**风险:** 高危，允许远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-10-27  
**POC仓库:** [CVE-2021-22204](https://github.com/PenTestical/CVE-2021-22204)  

---

### [CVE-2021-22204](CVE-2021-22204-AssassinUKG_CVE-2021-22204.md) 🔴 ✅

**名称:** CVE-2021-22204 - ExifTool DjVu 远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器被控制  
**投毒风险:** 5%  
**发现时间:** 2025-10-27  
**POC仓库:** [CVE-2021-22204](https://github.com/AssassinUKG/CVE-2021-22204)  

---

### [CVE-2021-22204](CVE-2021-22204-ph-arm_CVE-2021-22204-Gitlab.md) 🔴 ✅

**名称:** CVE-2021-22204-ExifTool-RCE  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-10-27  
**POC仓库:** [CVE-2021-22204-Gitlab](https://github.com/ph-arm/CVE-2021-22204-Gitlab)  

---

### [CVE-2021-22204](CVE-2021-22204-trganda_CVE-2021-22204.md) 🔴 ✅

**名称:** CVE-2021-22204-ExifTool-DjVu-代码执行  
**类型:** 代码执行  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-10-27  
**POC仓库:** [CVE-2021-22204](https://github.com/trganda/CVE-2021-22204)  

---

### [CVE-2021-22204](CVE-2021-22204-0xBruno_CVE-2021-22204.md) 🔴 ✅

**名称:** CVE-2021-22204 ExifTool DjVu 远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可导致服务器被完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-10-27  
**POC仓库:** [CVE-2021-22204](https://github.com/0xBruno/CVE-2021-22204)  

---

### [CVE-2021-22204](CVE-2021-22204-mr-tuhin_CVE-2021-22204-exiftool.md) 🔴 ✅

**名称:** CVE-2021-22204-ExifTool-代码执行  
**类型:** 代码执行  
**风险:** 高危，允许远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-10-27  
**POC仓库:** [CVE-2021-22204-exiftool](https://github.com/mr-tuhin/CVE-2021-22204-exiftool)  

---

### [CVE-2021-22204](CVE-2021-22204-Akash7350_CVE-2021-22204.md) 🔴 ✅

**名称:** CVE-2021-22204-ExifTool-代码执行  
**类型:** 代码执行  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-10-27  
**POC仓库:** [CVE-2021-22204](https://github.com/Akash7350/CVE-2021-22204)  

---

### [CVE-2021-22204](CVE-2021-22204-battleofthebots_dejavu.md) 🔴 ✅

**名称:** CVE-2021-22204 ExifTool DjVu 远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可导致服务器被完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-10-27  
**POC仓库:** [dejavu](https://github.com/battleofthebots/dejavu)  

---

### [CVE-2021-22204](CVE-2021-22204-cc3305_CVE-2021-22204.md) 🔴 ✅

**名称:** CVE-2021-22204 - ExifTool DjVu 任意代码执行  
**类型:** 代码执行  
**风险:** 高危，允许攻击者执行任意代码  
**投毒风险:** 1%  
**发现时间:** 2025-10-27  
**POC仓库:** [CVE-2021-22204](https://github.com/cc3305/CVE-2021-22204)  

---

### [CVE-2021-22204](CVE-2021-22204-UNICORDev_exploit-CVE-2021-22204.md) 🔴 ✅

**名称:** CVE-2021-22204-ExifTool-代码执行  
**类型:** 代码执行  
**风险:** 高危，允许任意代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-10-27  
**POC仓库:** [exploit-CVE-2021-22204](https://github.com/UNICORDev/exploit-CVE-2021-22204)  

---

### [CVE-2021-22204](CVE-2021-22204-sameep0_CVE-2021-22204.md) 🔴 ✅

**名称:** CVE-2021-22204-ExifTool-代码执行  
**类型:** 代码执行  
**风险:** 高危，允许攻击者执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-10-27  
**POC仓库:** [CVE-2021-22204](https://github.com/sameep0/CVE-2021-22204)  

---

### [CVE-2021-22204](CVE-2021-22204-Roronoawjd_CVE-2021-22204.md) 🔴 ✅

**名称:** CVE-2021-22204-ExifTool-DjVu模块代码注入  
**类型:** 代码注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-10-27  
**POC仓库:** [CVE-2021-22204](https://github.com/Roronoawjd/CVE-2021-22204)  

---

### [CVE-2025-53072](CVE-2025-53072-AshrafZaryouh_CVE-2025-53072-CVE-2025-62481.md) 🔴 

**名称:** CVE-2025-53072 Oracle Marketing 远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可导致服务器完全控制  
**投毒风险:** 5%  
**发现时间:** 2025-10-27  
**POC仓库:** [CVE-2025-53072-CVE-2025-62481](https://github.com/AshrafZaryouh/CVE-2025-53072-CVE-2025-62481)  

---

### [CVE-2025-59287](CVE-2025-59287-RadzaRr_WSUSResponder.md)  ✅

**名称:** CVE-2025-59287-WSUS-RCE  
**类型:** 远程代码执行  
**风险:** 严重，可能导致系统完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-10-27  
**POC仓库:** [WSUSResponder](https://github.com/RadzaRr/WSUSResponder)  

---

### [CVE-2025-61884](CVE-2025-61884-AshrafZaryouh_CVE-2025-61884-At-a-Glance.md) 🔴 ✅

**名称:** CVE-2025-61884-Oracle Configurator信息泄露  
**类型:** 信息泄露  
**风险:** 高危，可能导致敏感信息泄露，为后续攻击提供便利  
**投毒风险:** 0%  
**发现时间:** 2025-10-27  
**POC仓库:** [CVE-2025-61884-At-a-Glance](https://github.com/AshrafZaryouh/CVE-2025-61884-At-a-Glance)  

---

### [CVE-2021-31166](CVE-2021-31166-zha0gongz1_CVE-2021-31166.md) 🔴 ✅

**名称:** CVE-2021-31166 - HTTP Protocol Stack Remote Code Execution Vulnerability  
**类型:** Use-After-Free  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-10-27  
**POC仓库:** [CVE-2021-31166](https://github.com/zha0gongz1/CVE-2021-31166)  

---

### [CVE-2021-31166](CVE-2021-31166-zecopro_CVE-2021-31166.md) 🔴 ✅

**名称:** CVE-2021-31166 HTTP Protocol Stack Remote Code Execution Vulnerability  
**类型:** 远程代码执行  
**风险:** 高危，远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-10-27  
**POC仓库:** [CVE-2021-31166](https://github.com/zecopro/CVE-2021-31166)  

---

### [CVE-2021-31166](CVE-2021-31166-bgsilvait_WIn-CVE-2021-31166.md) 🔴 ✅

**名称:** CVE-2021-31166 - HTTP Protocol Stack Remote Code Execution  
**类型:** 远程代码执行  
**风险:** 高危，可能导致系统完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-10-27  
**POC仓库:** [WIn-CVE-2021-31166](https://github.com/bgsilvait/WIn-CVE-2021-31166)  

---

### [CVE-2021-31166](CVE-2021-31166-0vercl0k_CVE-2021-31166.md) 🔴 ✅

**名称:** CVE-2021-31166: HTTP Protocol Stack Remote Code Execution Vulnerability  
**类型:** 远程代码执行  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-10-27  
**POC仓库:** [CVE-2021-31166](https://github.com/0vercl0k/CVE-2021-31166)  

---

### [CVE-2021-31166](CVE-2021-31166-y0g3sh-99_CVE-2021-31166-Exploit.md) 🔴 ✅

**名称:** CVE-2021-31166-HTTP Protocol Stack Remote Code Execution Vulnerability  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-10-27  
**POC仓库:** [CVE-2021-31166-Exploit](https://github.com/y0g3sh-99/CVE-2021-31166-Exploit)  

---

### [CVE-2021-31166](CVE-2021-31166-imikoYa_CVE-2021-31166-exploit.md) 🔴 ✅

**名称:** CVE-2021-31166 (HTTP Protocol Stack Remote Code Execution Vulnerability)  
**类型:** 远程代码执行  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-10-27  
**POC仓库:** [CVE-2021-31166-exploit](https://github.com/imikoYa/CVE-2021-31166-exploit)  

---

### [CVE-2021-31166](CVE-2021-31166-ZZ-SOCMAP_CVE-2021-31166.md) 🔴 ✅

**名称:** CVE-2021-31166 HTTP Protocol Stack Remote Code Execution Vulnerability  
**类型:** 远程代码执行  
**风险:** 高危，可导致远程代码执行，系统蓝屏  
**投毒风险:** 0%  
**发现时间:** 2025-10-27  
**POC仓库:** [CVE-2021-31166](https://github.com/ZZ-SOCMAP/CVE-2021-31166)  

---

### [CVE-2021-31166](CVE-2021-31166-mvlnetdev_CVE-2021-31166-detection-rules.md) 🔴 ✅

**名称:** CVE-2021-31166 HTTP Protocol Stack Remote Code Execution Vulnerability  
**类型:** 远程代码执行  
**风险:** 高危，可导致远程代码执行，完全控制受影响系统  
**投毒风险:** 10%  
**发现时间:** 2025-10-27  
**POC仓库:** [CVE-2021-31166-detection-rules](https://github.com/mvlnetdev/CVE-2021-31166-detection-rules)  

---

### [CVE-2021-31166](CVE-2021-31166-mauricelambert_CVE-2021-31166.md) 🔴 ✅

**名称:** CVE-2021-31166 - HTTP Protocol Stack Remote Code Execution  
**类型:** 远程代码执行 (RCE)/拒绝服务 (DoS)  
**风险:** 高危，可导致远程代码执行或拒绝服务  
**投毒风险:** 0%  
**发现时间:** 2025-10-27  
**POC仓库:** [CVE-2021-31166](https://github.com/mauricelambert/CVE-2021-31166)  

---

### [CVE-2021-31166](CVE-2021-31166-0xmaximus_Home-Demolisher.md) 🔴 ✅

**名称:** CVE-2021-31166 HTTP Protocol Stack Remote Code Execution Vulnerability  
**类型:** 远程代码执行  
**风险:** 高危，远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-10-27  
**POC仓库:** [Home-Demolisher](https://github.com/0xmaximus/Home-Demolisher)  

---

### [CVE-2021-31166](CVE-2021-31166-corelight_CVE-2021-31166.md) 🔴 ✅

**名称:** CVE-2021-31166  
**类型:** 远程代码执行  
**风险:** 高危，远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-10-27  
**POC仓库:** [CVE-2021-31166](https://github.com/corelight/CVE-2021-31166)  

---

### [CVE-2024-39840](CVE-2024-39840-writegsqword_CVE-2024-39840-POC.md) 🔴 ✅

**名称:** CVE-2024-39840 - Factorio RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，允许远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-10-27  
**POC仓库:** [CVE-2024-39840-POC](https://github.com/writegsqword/CVE-2024-39840-POC)  

---

### [CVE-2025-59287](CVE-2025-59287-tecxx_CVE-2025-59287-WSUS.md) 🔴 ✅

**名称:** CVE-2025-59287-WSUS Remote Code Execution  
**类型:** 反序列化漏洞  
**风险:** 高危，允许未经授权的攻击者通过网络执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-10-27  
**POC仓库:** [CVE-2025-59287-WSUS](https://github.com/tecxx/CVE-2025-59287-WSUS)  

---

### [CVE-2025-29824](CVE-2025-29824-zmkeh_CVE-2025-29824-CLFS-Local-privilege-escalation.md) 🔴 ✅

**名称:** CVE-2025-29824 Windows Common Log File System Driver Elevation of Privilege Vulnerability  
**类型:** 权限提升 (Elevation of Privilege)  
**风险:** 高危，本地权限提升  
**投毒风险:** 10%  
**发现时间:** 2025-10-27  
**POC仓库:** [CVE-2025-29824-CLFS-Local-privilege-escalation](https://github.com/zmkeh/CVE-2025-29824-CLFS-Local-privilege-escalation)  

---

### [CVE-2025-56521](CVE-2025-56521-Dong-hui-li_CVE-2025-56521andCVE-2025-56522.md) 🔴 ✅

**名称:** CVE-2025-56521 Clang编译器优化错误和Clang编译崩溃漏洞  
**类型:** 编译器错误/崩溃  
**风险:** 中危/高危，可能导致程序行为异常或拒绝服务  
**投毒风险:** 1%  
**发现时间:** 2025-10-27  
**POC仓库:** [CVE-2025-56521andCVE-2025-56522](https://github.com/Dong-hui-li/CVE-2025-56521andCVE-2025-56522)  

---

### [CVE-2020-11978](CVE-2020-11978-stuxbench_mlflow-cve-2020-11978.md) 🔴 ✅

**名称:** CVE-2020-11978-Apache Airflow-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，允许认证用户以Airflow worker/scheduler的身份执行任意命令  
**投毒风险:** 10%  
**发现时间:** 2025-10-27  
**POC仓库:** [mlflow-cve-2020-11978](https://github.com/stuxbench/mlflow-cve-2020-11978)  

---

### [CVE-2025-49844](CVE-2025-49844-Zain3311_CVE-2025-49844.md) 🔴 

**名称:** CVE-2025-49844-Redis-Lua-Use-After-Free  
**类型:** Use-After-Free  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 99%  
**发现时间:** 2025-10-27  
**POC仓库:** [CVE-2025-49844](https://github.com/Zain3311/CVE-2025-49844)  

---

### [CVE-2025-49844](CVE-2025-49844-ksnnd32_redis_exploit.md) 🔴 

**名称:** CVE-2025-49844-Redis-Lua Use-After-Free  
**类型:** Use-After-Free  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-10-27  
**POC仓库:** [redis_exploit](https://github.com/ksnnd32/redis_exploit)  

---

### [CVE-2023-49440](CVE-2023-49440-KernelCipher_CVE-2023-49440-POC.md) 🔴 ✅

**名称:** CVE-2023-49440-AhnLab EPP Management SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-10-27  
**POC仓库:** [CVE-2023-49440-POC](https://github.com/KernelCipher/CVE-2023-49440-POC)  

---

### [CVE-2025-59287](CVE-2025-59287-0xBruno_WSUSploit.NET.md) 🔴 ✅

**名称:** CVE-2025-59287-Windows Server Update Service (WSUS) Remote Code Execution Vulnerability  
**类型:** 反序列化漏洞  
**风险:** 高危，远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-10-27  
**POC仓库:** [WSUSploit.NET](https://github.com/0xBruno/WSUSploit.NET)  

---

### [CVE-2025-59287](CVE-2025-59287-Lupovis_Honeypot-for-CVE-2025-59287-WSUS.md) 🔴 

**名称:** CVE-2025-59287-Windows Server Update Service (WSUS) Remote Code Execution Vulnerability  
**类型:** 反序列化漏洞  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-10-27  
**POC仓库:** [Honeypot-for-CVE-2025-59287-WSUS](https://github.com/Lupovis/Honeypot-for-CVE-2025-59287-WSUS)  

---

### [CVE-2025-11534](CVE-2025-11534-ZeroByte8_CVE-2025-11534.md) 🔴 ✅

**名称:** CVE-2025-11534 - Raisecomm RAX701-GC-WP-01 SSH 身份验证绕过  
**类型:** 身份验证绕过  
**风险:** 高危，未经授权的远程访问  
**投毒风险:** 10%  
**发现时间:** 2025-10-27  
**POC仓库:** [CVE-2025-11534](https://github.com/ZeroByte8/CVE-2025-11534)  

---

### [CVE-2023-49440](CVE-2023-49440-KernelCipher_CVE-2023-49440-POC.md) 🔴 

**名称:** CVE-2023-49440-AhnLab EPP Management-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-10-27  
**POC仓库:** [CVE-2023-49440-POC](https://github.com/KernelCipher/CVE-2023-49440-POC)  

---

### [CVE-2025-22167](CVE-2025-22167-issamjr_CVE-2025-22167.md) 🔴 ✅

**名称:** CVE-2025-22167-Jira-路径遍历任意文件写入  
**类型:** 路径遍历/任意文件写入  
**风险:** 高危，允许修改 Jira JVM 进程可写的任何文件系统路径，可能导致数据损坏、webshell 植入或 RCE  
**投毒风险:** 5%  
**发现时间:** 2025-10-27  
**POC仓库:** [CVE-2025-22167](https://github.com/issamjr/CVE-2025-22167)  

---

### [CVE-2025-11534](CVE-2025-11534-DExplo1ted_CVE-2025-11534-POC.md) 🔴 ✅

**名称:** CVE-2025-11534 - Raisecomm RAX701-GC-WP-01 SSH Authentication Bypass  
**类型:** Authentication Bypass  
**风险:** 高危，攻击者可以完全控制设备  
**投毒风险:** 10%  
**发现时间:** 2025-10-27  
**POC仓库:** [CVE-2025-11534-POC](https://github.com/DExplo1ted/CVE-2025-11534-POC)  

---

### [CVE-2025-11534](CVE-2025-11534-snareloop_CVE-2025-11534.md)  ✅

**名称:** CVE-2025-11534 - Raisecomm RAX701-GC-WP-01 SSH 认证绕过  
**类型:** SSH认证绕过  
**风险:** 严重，允许未经授权的远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-10-27  
**POC仓库:** [CVE-2025-11534](https://github.com/snareloop/CVE-2025-11534)  

---

### [CVE-2020-29607](CVE-2020-29607-ar2o3_CVE-2020-29607.md) 🔴 ✅

**名称:** CVE-2020-29607-Pluck CMS-文件上传绕过  
**类型:** 文件上传绕过  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-10-27  
**POC仓库:** [CVE-2020-29607](https://github.com/ar2o3/CVE-2020-29607)  

---

### [CVE-2020-29607](CVE-2020-29607-0xN7y_CVE-2020-29607.md) 🔴 ✅

**名称:** CVE-2020-29607-Pluck CMS-文件上传绕过导致远程代码执行  
**类型:** 文件上传绕过  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-10-27  
**POC仓库:** [CVE-2020-29607](https://github.com/0xN7y/CVE-2020-29607)  

---

### [CVE-2020-29607](CVE-2020-29607-Alienfader_CVE-2020-29607.md) 🔴 ✅

**名称:** CVE-2020-29607-Pluck CMS-文件上传绕过导致远程代码执行  
**类型:** 文件上传绕过  
**风险:** 高危，允许攻击者上传恶意webshell并执行任意代码  
**投毒风险:** 5%  
**发现时间:** 2025-10-27  
**POC仓库:** [CVE-2020-29607](https://github.com/Alienfader/CVE-2020-29607)  

---

### [CVE-2020-29607](CVE-2020-29607-CaelumIsMe_CVE-2020-29607-POC.md) 🔴 ✅

**名称:** CVE-2020-29607-Pluck CMS-文件上传绕过导致RCE  
**类型:** 文件上传绕过  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-10-27  
**POC仓库:** [CVE-2020-29607-POC](https://github.com/CaelumIsMe/CVE-2020-29607-POC)  

---

### [CVE-2018-15473](CVE-2018-15473-makmour_open-ssh-user-enumeration.md) 🟡 ✅

**名称:** CVE-2018-15473 OpenSSH 用户名枚举漏洞  
**类型:** 用户名枚举  
**风险:** 中危，可能为后续攻击提供信息  
**投毒风险:** 1%  
**发现时间:** 2025-10-27  
**POC仓库:** [open-ssh-user-enumeration](https://github.com/makmour/open-ssh-user-enumeration)  

---

### [CVE-2018-15473](CVE-2018-15473-Alph4Sec_ssh_enum_py.md) 🟡 ✅

**名称:** CVE-2018-15473 OpenSSH 用户枚举漏洞  
**类型:** 用户枚举  
**风险:** 中危，允许攻击者枚举有效的用户名  
**投毒风险:** 1%  
**发现时间:** 2025-10-27  
**POC仓库:** [ssh_enum_py](https://github.com/Alph4Sec/ssh_enum_py)  

---

### [CVE-2018-15473](CVE-2018-15473-anonymous121029034720384234234_py-network-scanner.md)  ✅

**名称:** CVE-2018-15473-OpenSSH用户名枚举  
**类型:** 用户名枚举  
**风险:** 低危，可能为后续攻击提供信息  
**投毒风险:** 10%  
**发现时间:** 2025-10-27  
**POC仓库:** [py-network-scanner](https://github.com/anonymous121029034720384234234/py-network-scanner)  

---

### [CVE-2018-15473](CVE-2018-15473-jubeenshah_CVE-2018-15473-Exploit.md) 🟡 ✅

**名称:** CVE-2018-15473 OpenSSH 用户枚举漏洞  
**类型:** 用户枚举  
**风险:** 中危，可能为后续暴力破解或漏洞利用提供便利  
**投毒风险:** 10%  
**发现时间:** 2025-10-27  
**POC仓库:** [CVE-2018-15473-Exploit](https://github.com/jubeenshah/CVE-2018-15473-Exploit)  

---

### [CVE-2025-9967](CVE-2025-9967-glitchhawks_CVE-2025-9967.md)  ✅

**名称:** CVE-2025-9967 - WordPress Orion SMS OTP Verification Account Takeover  
**类型:** Authentication Bypass / Account Takeover  
**风险:** 严重，允许未经身份验证的攻击者接管任意用户帐户  
**投毒风险:** 80%  
**发现时间:** 2025-10-26  
**POC仓库:** [CVE-2025-9967](https://github.com/glitchhawks/CVE-2025-9967)  

---

### [CVE-2023-49440](CVE-2023-49440-KernelCipher_CVE-2023-49440-POC.md) 🔴 ✅

**名称:** 未识别漏洞-XXX服务器-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可导致敏感信息泄露，如管理员账号密码。  
**投毒风险:** 10%  
**发现时间:** 2025-10-26  
**POC仓库:** [CVE-2023-49440-POC](https://github.com/KernelCipher/CVE-2023-49440-POC)  

---

### [CVE-2024-23897](CVE-2024-23897-aadi0258_Exploit-CVE-2024-23897.md) 🔴 ✅

**名称:** CVE-2024-23897 - Jenkins Arbitrary File Read  
**类型:** 任意文件读取  
**风险:** 高危，可能导致敏感信息泄露和远程代码执行（取决于读取的文件内容）  
**投毒风险:** 0%  
**发现时间:** 2025-10-26  
**POC仓库:** [Exploit-CVE-2024-23897](https://github.com/aadi0258/Exploit-CVE-2024-23897)  

---

### [CVE-2025-49553](CVE-2025-49553-glitchhawks_CVE-2025-49553.md) 🔴 ✅

**名称:** CVE-2025-49553-Adobe Connect-DOM型XSS  
**类型:** DOM型XSS  
**风险:** 高危，可能导致会话劫持、信息泄露和权限提升  
**投毒风险:** 85%  
**发现时间:** 2025-10-26  
**POC仓库:** [CVE-2025-49553](https://github.com/glitchhawks/CVE-2025-49553)  

---

### [CVE-2025-62376](CVE-2025-62376-ghostroots_CVE-2025-62376.md) 🔴 ✅

**名称:** CVE-2025-62376-pwn.college DOJO-权限绕过  
**类型:** 权限绕过/不当身份验证  
**风险:** 高危，可完全控制目标Windows VM  
**投毒风险:** 5%  
**发现时间:** 2025-10-26  
**POC仓库:** [CVE-2025-62376](https://github.com/ghostroots/CVE-2025-62376)  

---

### [CVE-2025-55315](CVE-2025-55315-blackquantas_CVE-2025-55315.md) 🔴 ✅

**名称:** CVE-2025-55315-ASP.NET Security Feature Bypass  
**类型:** HTTP Request Smuggling  
**风险:** 高危，可能导致安全功能绕过，未授权访问和数据泄露  
**投毒风险:** 80%  
**发现时间:** 2025-10-26  
**POC仓库:** [CVE-2025-55315](https://github.com/blackquantas/CVE-2025-55315)  

---

### [CVE-2025-11832](CVE-2025-11832-blackhatlegend_CVE-2025-11832.md) 🔴 ✅

**名称:** CVE-2025-11832-BLU-IC2/IC4-资源耗尽  
**类型:** 资源耗尽 (Allocation of Resources Without Limits or Throttling)  
**风险:** 高危，可能导致服务中断和拒绝服务  
**投毒风险:** 95%  
**发现时间:** 2025-10-26  
**POC仓库:** [CVE-2025-11832](https://github.com/blackhatlegend/CVE-2025-11832)  

---

### [CVE-2025-53533](CVE-2025-53533-moezbouzayani9_Pi-hole-XSS-CVE-2025-53533.md) 🟡 ✅

**名称:** CVE-2025-53533 - Pi-hole Reflected XSS  
**类型:** Reflected Cross-Site Scripting (XSS)  
**风险:** 中危，可能导致用户凭据泄露，恶意脚本执行等  
**投毒风险:** 5%  
**发现时间:** 2025-10-26  
**POC仓库:** [Pi-hole-XSS-CVE-2025-53533](https://github.com/moezbouzayani9/Pi-hole-XSS-CVE-2025-53533)  

---

### [CVE-2025-61884](CVE-2025-61884-shinyhunt_CVE-2025-61884.md) 🔴 ✅

**名称:** CVE-2025-61884 - Oracle Configurator Unauthorized Data Access  
**类型:** 未经授权的数据访问  
**风险:** 高危，可能导致敏感数据泄露  
**投毒风险:** 80%  
**发现时间:** 2025-10-26  
**POC仓库:** [CVE-2025-61884](https://github.com/shinyhunt/CVE-2025-61884)  

---

### [CVE-2025-6514](CVE-2025-6514-Cyberency_CVE-2025-6514.md) 🔴 ✅

**名称:** CVE-2025-6514-mcp-remote-OS命令注入  
**类型:** OS命令注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-10-26  
**POC仓库:** [CVE-2025-6514](https://github.com/Cyberency/CVE-2025-6514)  

---

### [CVE-2024-32002](CVE-2024-32002-srakkk_cve-2024-32002-hook.md) 🔴 ✅

**名称:** CVE-2024-32002 - Git Recursive Clone Remote Code Execution  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-10-26  
**POC仓库:** [cve-2024-32002-hook](https://github.com/srakkk/cve-2024-32002-hook)  

---

### [CVE-2024-32002](CVE-2024-32002-srakkk_cve-2024-32002-demo.md) 🔴 ✅

**名称:** CVE-2024-32002-Git递归克隆远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，允许未经身份验证的攻击者在受害者机器上执行任意代码  
**投毒风险:** 5%  
**发现时间:** 2025-10-26  
**POC仓库:** [cve-2024-32002-demo](https://github.com/srakkk/cve-2024-32002-demo)  

---

### [CVE-2025-9983](CVE-2025-9983-sohaibeb_CVE-2025-9983.md) 🔴 ✅

**名称:** CVE-2025-9983 - GALAYOU G2 RTSP 无认证访问  
**类型:** 信息泄露  
**风险:** 高危，未经授权的视频流访问  
**投毒风险:** 1%  
**发现时间:** 2025-10-26  
**POC仓库:** [CVE-2025-9983](https://github.com/sohaibeb/CVE-2025-9983)  

---

### [CVE-2025-32463](CVE-2025-32463-DensuLabs_CVE-2025-32463.md) 🔴 

**名称:** CVE-2025-32463 Sudo 本地提权  
**类型:** 本地提权  
**风险:** 高危，允许本地用户获取root权限  
**投毒风险:** 0%  
**发现时间:** 2025-10-25  
**POC仓库:** [CVE-2025-32463](https://github.com/DensuLabs/CVE-2025-32463)  

---

### [CVE-2025-24893](CVE-2025-24893-rvizx_CVE-2025-24893.md) 🔴 ✅

**名称:** CVE-2025-24893-XWiki-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可导致完全控制受影响的XWiki服务器  
**投毒风险:** 5%  
**发现时间:** 2025-10-25  
**POC仓库:** [CVE-2025-24893](https://github.com/rvizx/CVE-2025-24893)  

---

### [CVE-2025-59287](CVE-2025-59287-garvitv14_CVE-2025-59287.md) 🔴 ✅

**名称:** CVE-2025-59287 WSUS RCE  
**类型:** 远程代码执行  
**风险:** 高危，未经身份验证的远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-10-25  
**POC仓库:** [CVE-2025-59287](https://github.com/garvitv14/CVE-2025-59287)  

---

### [CVE-2025-4334](CVE-2025-4334-vinodwick_CVE-2025-4334.md) 🔴 ✅

**名称:** CVE-2025-4334-Simple User Registration-权限提升  
**类型:** 权限提升  
**风险:** 高危，允许未经身份验证的攻击者注册为管理员  
**投毒风险:** 0%  
**发现时间:** 2025-10-25  
**POC仓库:** [CVE-2025-4334](https://github.com/vinodwick/CVE-2025-4334)  

---

### [CVE-2025-61304](CVE-2025-61304-pentastic-be_CVE-2025-61304.md) 🔴 ✅

**名称:** CVE-2025-61304 - Dynatrace ActiveGate OS Command Injection  
**类型:** OS 命令注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-10-25  
**POC仓库:** [CVE-2025-61304](https://github.com/pentastic-be/CVE-2025-61304)  

---

### [CVE-2019-7069](CVE-2019-7069-CaelumIsMe_CVE-2019-7069-POC.md) 🔴 ✅

**名称:** CVE-2019-7609 - Kibana Remote Code Execution  
**类型:** Remote Code Execution  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 5%  
**发现时间:** 2025-10-25  
**POC仓库:** [CVE-2019-7069-POC](https://github.com/CaelumIsMe/CVE-2019-7069-POC)  

---

### [CVE-2025-61882](CVE-2025-61882-siddu7575_CVE-2025-61882-CVE-2025-61884.md)  ✅

**名称:** CVE-2025-61882 - Oracle Concurrent Processing takeover  
**类型:** 远程代码执行 (RCE)  
**风险:** 严重，可能导致服务器完全控制  
**投毒风险:** 5%  
**发现时间:** 2025-10-25  
**POC仓库:** [CVE-2025-61882-CVE-2025-61884](https://github.com/siddu7575/CVE-2025-61882-CVE-2025-61884)  

---

### [CVE-2025-4796](CVE-2025-4796-Nxploited_CVE-2025-4796.md) 🔴 ✅

**名称:** CVE-2025-4796-Eventin-特权提升/账户接管  
**类型:** 特权提升/账户接管  
**风险:** 高危，可能导致账户接管和权限提升  
**投毒风险:** 1%  
**发现时间:** 2025-10-25  
**POC仓库:** [CVE-2025-4796](https://github.com/Nxploited/CVE-2025-4796)  

---

### [CVE-2025-59287](CVE-2025-59287-jiansiting_CVE-2025-59287.md)  ✅

**名称:** CVE-2025-59287-Windows Server Update Service (WSUS) 远程代码执行漏洞  
**类型:** 反序列化漏洞  
**风险:** 严重，可能导致远程代码执行并获取SYSTEM权限  
**投毒风险:** 10%  
**发现时间:** 2025-10-25  
**POC仓库:** [CVE-2025-59287](https://github.com/jiansiting/CVE-2025-59287)  

---

### [CVE-2025-48385](CVE-2025-48385-Mitchellzhou1_CVE-2025-48385-PoC.md) 🔴 ✅

**名称:** CVE-2025-48385-Git bundle-uri 参数注入导致任意文件写入  
**类型:** 参数注入/任意文件写入  
**风险:** 高危，可能导致任意代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-10-25  
**POC仓库:** [CVE-2025-48385-PoC](https://github.com/Mitchellzhou1/CVE-2025-48385-PoC)  

---

### [CVE-2025-61155](CVE-2025-61155-pollotherunner_CVE-2025-61155.md) 🔴 

**名称:** CVE-2025-61155 - GameDriverX64.sys 本地拒绝服务漏洞  
**类型:** 拒绝服务 (DoS)  
**风险:** 高危，可能导致系统崩溃  
**投毒风险:** 0%  
**发现时间:** 2025-10-24  
**POC仓库:** [CVE-2025-61155](https://github.com/pollotherunner/CVE-2025-61155)  

---

### [CVE-2025-60349](CVE-2025-60349-djackreuter_CVE-2025-60349.md) 🔴 ✅

**名称:** CVE-2025-60349: Pxscan Arbitrary Process Termination  
**类型:** 拒绝服务 (DoS)  
**风险:** 中危/高危，取决于被终止进程的重要性。可能导致系统不稳定或功能失效。  
**投毒风险:** 10%  
**发现时间:** 2025-10-24  
**POC仓库:** [CVE-2025-60349](https://github.com/djackreuter/CVE-2025-60349)  

---

### [CVE-2025-1550](CVE-2025-1550-ChCh0i_cve-2025-1550.md) 🔴 ✅

**名称:** CVE-2025-1550-Keras-RCE  
**类型:** 代码注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-10-24  
**POC仓库:** [cve-2025-1550](https://github.com/ChCh0i/cve-2025-1550)  

---

### [CVE-2025-55315](CVE-2025-55315-jlinebau_CVE-2025-55315-Scanner-Monitor.md) 🔴 ✅

**名称:** CVE-2025-55315 ASP.NET Security Feature Bypass Vulnerability (HTTP Request Smuggling)  
**类型:** HTTP Request Smuggling  
**风险:** 高危，可能导致安全特性绕过，信息泄露，权限提升，以及其他攻击。  
**投毒风险:** 10%  
**发现时间:** 2025-10-24  
**POC仓库:** [CVE-2025-55315-Scanner-Monitor](https://github.com/jlinebau/CVE-2025-55315-Scanner-Monitor)  

---

### [CVE-2025-3248](CVE-2025-3248-bambooqj_cve-2025-3248.md) 🔴 ✅

**名称:** CVE-2025-3248-Langflow-RCE  
**类型:** 远程代码执行  
**风险:** 高危，允许未经身份验证的远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-10-24  
**POC仓库:** [cve-2025-3248](https://github.com/bambooqj/cve-2025-3248)  

---

### [CVE-2020-11978](CVE-2020-11978-pberba_CVE-2020-11978.md) 🔴 ✅

**名称:** CVE-2020-11978-Apache Airflow-远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，允许经过身份验证的用户以运行 Airflow worker/scheduler 的用户身份执行任意命令  
**投毒风险:** 0%  
**发现时间:** 2025-10-24  
**POC仓库:** [CVE-2020-11978](https://github.com/pberba/CVE-2020-11978)  

---

### [CVE-2025-56399](CVE-2025-56399-Theethat-Thamwasin_CVE-2025-56399.md) 🔴 ✅

**名称:** CVE-2025-56399 - laravel-file-manager Authenticated Remote Code Execution  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，允许认证后的攻击者执行任意代码  
**投毒风险:** 5%  
**发现时间:** 2025-10-24  
**POC仓库:** [CVE-2025-56399](https://github.com/Theethat-Thamwasin/CVE-2025-56399)  

---

### [CVE-2023-22515](CVE-2023-22515-Arkha-Corvus_LetsDefend-SOC235-Atlassian-Confluence-Broken-Access-Control-0-Day-CVE-2023-22515-EventID-197.md) 🔴 ✅

**名称:** CVE-2023-22515-Atlassian Confluence 权限绕过  
**类型:** 权限绕过  
**风险:** 高危，允许未经身份验证的攻击者创建管理员账户  
**投毒风险:** 0%  
**发现时间:** 2025-10-24  
**POC仓库:** [LetsDefend-SOC235-Atlassian-Confluence-Broken-Access-Control-0-Day-CVE-2023-22515-EventID-197](https://github.com/Arkha-Corvus/LetsDefend-SOC235-Atlassian-Confluence-Broken-Access-Control-0-Day-CVE-2023-22515-EventID-197)  

---

### [CVE-2025-52099](CVE-2025-52099-SCREAMBBY_CVE-2025-52099.md) 🔴 

**名称:** CVE-2025-52099-SQLite Integer Overflow  
**类型:** Integer Overflow  
**风险:** 高危，可能导致崩溃、内存破坏或代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-10-24  
**POC仓库:** [CVE-2025-52099](https://github.com/SCREAMBBY/CVE-2025-52099)  

---

### [CVE-2025-59503](CVE-2025-59503-Mpokes_CVE-2025-59503-Poc.md) 🔴 ✅

**名称:** CVE-2025-59503-Azure Compute Resource Provider SSRF漏洞  
**类型:** SSRF  
**风险:** 高危，可能导致权限提升，网络信息泄露  
**投毒风险:** 95%  
**发现时间:** 2025-10-24  
**POC仓库:** [CVE-2025-59503-Poc](https://github.com/Mpokes/CVE-2025-59503-Poc)  

---

### [CVE-2025-61882](CVE-2025-61882-godnish_CVE-2025-61882.md) 🔴 ✅

**名称:** CVE-2025-61882-Oracle Concurrent Processing-RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-10-24  
**POC仓库:** [CVE-2025-61882](https://github.com/godnish/CVE-2025-61882)  

---

### [CVE-2025-61984](CVE-2025-61984-flyskyfire_cve-2025-61984-poc.md) 🟡 ✅

**名称:** CVE-2025-61984-OpenSSH-用户名控制字符注入  
**类型:** 命令注入  
**风险:** 中危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-10-24  
**POC仓库:** [cve-2025-61984-poc](https://github.com/flyskyfire/cve-2025-61984-poc)  

---

### [CVE-2025-60749](CVE-2025-60749-yawataa_CVE-2025-60749.md) 🔴 ✅

**名称:** CVE-2025-60749 SketchUp Desktop 2025 DLL Hijacking Vulnerability  
**类型:** DLL劫持  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-10-24  
**POC仓库:** [CVE-2025-60749](https://github.com/yawataa/CVE-2025-60749)  

---

### [CVE-2024-56800](CVE-2024-56800-cyhe50_cve-2024-56800-poc.md) 🔴 ✅

**名称:** CVE-2024-56800-Firecrawl-SSRF  
**类型:** SSRF (服务器端请求伪造)  
**风险:** 高危，可能导致内部网络资源泄露和访问  
**投毒风险:** 10%  
**发现时间:** 2025-10-24  
**POC仓库:** [cve-2024-56800-poc](https://github.com/cyhe50/cve-2024-56800-poc)  

---

### [CVE-2019-18935](CVE-2019-18935-menashe12346_CVE-2019-18935.md) 🔴 ✅

**名称:** CVE-2019-18935-Telerik UI for ASP.NET AJAX-反序列化漏洞  
**类型:** 反序列化漏洞  
**风险:** 高危，远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-10-23  
**POC仓库:** [CVE-2019-18935](https://github.com/menashe12346/CVE-2019-18935)  

---

### [CVE-2025-62481](CVE-2025-62481-callinston_CVE-2025-62481.md) 🔴 ✅

**名称:** CVE-2025-62481-Oracle Marketing-RCE  
**类型:** 远程代码执行  
**风险:** 高危，可完全控制Oracle Marketing系统  
**投毒风险:** 60%  
**发现时间:** 2025-10-23  
**POC仓库:** [CVE-2025-62481](https://github.com/callinston/CVE-2025-62481)  

---

### [CVE-2025-8088](CVE-2025-8088-mocred_cve-2025-8088.md) 🔴 ✅

**名称:** CVE-2025-8088 WinRAR path traversal  
**类型:** Path Traversal  
**风险:** 高危，允许攻击者执行任意代码  
**投毒风险:** 95%  
**发现时间:** 2025-10-23  
**POC仓库:** [cve-2025-8088](https://github.com/mocred/cve-2025-8088)  

---

### [CVE-2025-61932](CVE-2025-61932-allinsthon_CVE-2025-61932.md) 🔴 ✅

**名称:** CVE-2025-61932-Lanscope Endpoint Manager RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，未经身份验证的远程代码执行，可能导致完全控制受影响系统  
**投毒风险:** 10%  
**发现时间:** 2025-10-23  
**POC仓库:** [CVE-2025-61932](https://github.com/allinsthon/CVE-2025-61932)  

---

### [CVE-2025-48148](CVE-2025-48148-Nxploited_CVE-2025-48148.md) 🔴 ✅

**名称:** CVE-2025-48148-StoreKeeper for WooCommerce-任意文件上传  
**类型:** 任意文件上传  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-10-23  
**POC仓库:** [CVE-2025-48148](https://github.com/Nxploited/CVE-2025-48148)  

---

### [CVE-2025-62506](CVE-2025-62506-yoshino-s_CVE-2025-62506.md) 🔴 ✅

**名称:** CVE-2025-62506-MinIO-权限提升  
**类型:** 权限提升  
**风险:** 高危，允许低权限用户提升至完全控制权限  
**投毒风险:** 10%  
**发现时间:** 2025-10-23  
**POC仓库:** [CVE-2025-62506](https://github.com/yoshino-s/CVE-2025-62506)  

---

### [CVE-2024-38063](CVE-2024-38063-akozsentre_CVE-2024-38063.md) 🔴 ✅

**名称:** CVE-2024-38063-Windows TCP/IP RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致系统完全控制  
**投毒风险:** 80%  
**发现时间:** 2025-10-23  
**POC仓库:** [CVE-2024-38063](https://github.com/akozsentre/CVE-2024-38063)  

---

### [CVE-2025-60424](CVE-2025-60424-aakashtyal_2FA-Bypass-using-a-Brute-Force-Attack-CVE-2025-60424.md) 🔴 ✅

**名称:** Nagios Fusion 2FA Bypass Using a Brute Force Attack  
**类型:** 2FA绕过  
**风险:** 高危，可能导致未授权访问敏感账户，包括管理员账户，最终导致数据泄露或系统控制  
**投毒风险:** 0%  
**发现时间:** 2025-10-23  
**POC仓库:** [2FA-Bypass-using-a-Brute-Force-Attack-CVE-2025-60424](https://github.com/aakashtyal/2FA-Bypass-using-a-Brute-Force-Attack-CVE-2025-60424)  

---

### [CVE-2025-60425](CVE-2025-60425-aakashtyal_Session-Persistence-After-Enabling-2FA-CVE-2025-60425.md) 🔴 ✅

**名称:** Nagios Fusion 2FA绕过漏洞  
**类型:** 身份验证绕过  
**风险:** 高危，可能导致未经授权的访问和权限提升  
**投毒风险:** 10%  
**发现时间:** 2025-10-23  
**POC仓库:** [Session-Persistence-After-Enabling-2FA-CVE-2025-60425](https://github.com/aakashtyal/Session-Persistence-After-Enabling-2FA-CVE-2025-60425)  

---

### [CVE-2025-29891](CVE-2025-29891-Crystallen1_CVE-2025-29891-demo.md) 🔴 ✅

**名称:** CVE-2025-29891 - Apache Camel Message Header Injection  
**类型:** Header Injection/Bypass  
**风险:** 高危，可能导致远程代码执行或信息泄露  
**投毒风险:** 1%  
**发现时间:** 2025-10-23  
**POC仓库:** [CVE-2025-29891-demo](https://github.com/Crystallen1/CVE-2025-29891-demo)  

---

### [CVE-2021-3493](CVE-2021-3493-Abdennour-py_CVE-2021-3493.md) 🔴 ✅

**名称:** CVE-2021-3493 Ubuntu OverlayFS 本地提权  
**类型:** 本地提权  
**风险:** 高危，可导致普通用户提升为root权限  
**投毒风险:** 0%  
**发现时间:** 2025-10-23  
**POC仓库:** [CVE-2021-3493](https://github.com/Abdennour-py/CVE-2021-3493)  

---

### [CVE-2021-3493](CVE-2021-3493-puckiestyle_CVE-2021-3493.md) 🔴 ✅

**名称:** CVE-2021-3493 - Ubuntu OverlayFS 本地提权  
**类型:** 本地提权  
**风险:** 高危，攻击者可利用此漏洞获得 root 权限  
**投毒风险:** 10%  
**发现时间:** 2025-10-23  
**POC仓库:** [CVE-2021-3493](https://github.com/puckiestyle/CVE-2021-3493)  

---

### [CVE-2025-61882](CVE-2025-61882-BattalionX_http-oracle-ebs-cve-2025-61882.nse.md) 🔴 ✅

**名称:** CVE-2025-61882-Oracle Concurrent Processing-未授权访问  
**类型:** 未授权访问  
**风险:** 高危，可能导致完全控制Oracle Concurrent Processing  
**投毒风险:** 1%  
**发现时间:** 2025-10-23  
**POC仓库:** [http-oracle-ebs-cve-2025-61882.nse](https://github.com/BattalionX/http-oracle-ebs-cve-2025-61882.nse)  

---

### [CVE-2025-61882](CVE-2025-61882-godnish_CVE-2025-61882.md) 🔴 ✅

**名称:** CVE-2025-61882-Oracle Concurrent Processing-RCE  
**类型:** 远程代码执行  
**风险:** 高危，可完全控制受影响的 Oracle Concurrent Processing 系统。  
**投毒风险:** 10%  
**发现时间:** 2025-10-23  
**POC仓库:** [CVE-2025-61882](https://github.com/godnish/CVE-2025-61882)  

---

### [CVE-2025-57870](CVE-2025-57870-ByteHawkSec_CVE-2025-57870-POC.md)  ✅

**名称:** CVE-2025-57870 - Esri ArcGIS Server SQL注入  
**类型:** SQL注入  
**风险:** 严重，可能导致数据泄露、数据修改、数据删除以及远程代码执行  
**投毒风险:** 85%  
**发现时间:** 2025-10-23  
**POC仓库:** [CVE-2025-57870-POC](https://github.com/ByteHawkSec/CVE-2025-57870-POC)  

---

### [CVE-2021-3493](CVE-2021-3493-oneoy_CVE-2021-3493.md) 🔴 ✅

**名称:** CVE-2021-3493 - Ubuntu OverlayFS 本地提权  
**类型:** 本地提权  
**风险:** 高危，本地用户可提升至 root 权限  
**投毒风险:** 0%  
**发现时间:** 2025-10-23  
**POC仓库:** [CVE-2021-3493](https://github.com/oneoy/CVE-2021-3493)  

---

### [CVE-2021-3493](CVE-2021-3493-inspiringz_CVE-2021-3493.md) 🔴 ✅

**名称:** CVE-2021-3493-Ubuntu OverlayFS 本地提权  
**类型:** 本地提权  
**风险:** 高危，允许低权限用户提升到root权限  
**投毒风险:** 5%  
**发现时间:** 2025-10-23  
**POC仓库:** [CVE-2021-3493](https://github.com/inspiringz/CVE-2021-3493)  

---

### [CVE-2021-3493](CVE-2021-3493-derek-turing_CVE-2021-3493.md) 🔴 ✅

**名称:** CVE-2021-3493-Ubuntu OverlayFS 本地提权  
**类型:** 本地提权  
**风险:** 高危，本地用户可提升至 root 权限  
**投毒风险:** 0%  
**发现时间:** 2025-10-23  
**POC仓库:** [CVE-2021-3493](https://github.com/derek-turing/CVE-2021-3493)  

---

### [CVE-2021-3493](CVE-2021-3493-pmihsan_OverlayFS-CVE-2021-3493.md) 🔴 ✅

**名称:** CVE-2021-3493-Ubuntu OverlayFS 本地提权  
**类型:** 本地提权  
**风险:** 高危，本地用户可提升至 root 权限  
**投毒风险:** 0%  
**发现时间:** 2025-10-23  
**POC仓库:** [OverlayFS-CVE-2021-3493](https://github.com/pmihsan/OverlayFS-CVE-2021-3493)  

---

### [CVE-2021-3493](CVE-2021-3493-ptkhai15_OverlayFS---CVE-2021-3493.md) 🔴 ✅

**名称:** CVE-2021-3493-Ubuntu OverlayFS 本地提权  
**类型:** 本地提权  
**风险:** 高危，允许本地用户提升权限至 root  
**投毒风险:** 0%  
**发现时间:** 2025-10-23  
**POC仓库:** [OverlayFS---CVE-2021-3493](https://github.com/ptkhai15/OverlayFS---CVE-2021-3493)  

---

### [CVE-2021-3493](CVE-2021-3493-briskets_CVE-2021-3493.md) 🔴 ✅

**名称:** CVE-2021-3493 - Ubuntu OverlayFS 本地提权  
**类型:** 本地提权  
**风险:** 高危，可导致普通用户权限提升至root权限  
**投毒风险:** 5%  
**发现时间:** 2025-10-23  
**POC仓库:** [CVE-2021-3493](https://github.com/briskets/CVE-2021-3493)  

---

### [CVE-2021-3493](CVE-2021-3493-iamz24_CVE-2021-3493_CVE-2022-3357.md) 🔴 ✅

**名称:** CVE-2021-3493 - Ubuntu OverlayFS 本地提权漏洞  
**类型:** 本地提权  
**风险:** 高危，可导致本地权限提升至 root  
**投毒风险:** 10%  
**发现时间:** 2025-10-23  
**POC仓库:** [CVE-2021-3493_CVE-2022-3357](https://github.com/iamz24/CVE-2021-3493_CVE-2022-3357)  

---

### [CVE-2021-3493](CVE-2021-3493-fathallah17_OverlayFS-CVE-2021-3493.md) 🔴 ✅

**名称:** CVE-2021-3493 - Ubuntu OverlayFS 本地提权  
**类型:** 本地权限提升  
**风险:** 高危，可导致本地权限提升至root  
**投毒风险:** 1%  
**发现时间:** 2025-10-23  
**POC仓库:** [OverlayFS-CVE-2021-3493](https://github.com/fathallah17/OverlayFS-CVE-2021-3493)  

---

### [CVE-2021-3493](CVE-2021-3493-Sornphut_OverlayFS---CVE-2021-3493.md) 🔴 ✅

**名称:** CVE-2021-3493 - Ubuntu OverlayFS 本地提权漏洞  
**类型:** 本地提权  
**风险:** 高危，允许本地用户获得 root 权限  
**投毒风险:** 0%  
**发现时间:** 2025-10-23  
**POC仓库:** [OverlayFS---CVE-2021-3493](https://github.com/Sornphut/OverlayFS---CVE-2021-3493)  

---

### [CVE-2021-3493](CVE-2021-3493-spideyctf_UbuntuTouchSecurityVAPTReport.md) 🔴 ✅

**名称:** CVE-2021-3493-Ubuntu OverlayFS 本地提权  
**类型:** 权限提升  
**风险:** 高危，攻击者可以利用此漏洞从普通用户提升到root权限  
**投毒风险:** 5%  
**发现时间:** 2025-10-23  
**POC仓库:** [UbuntuTouchSecurityVAPTReport](https://github.com/spideyctf/UbuntuTouchSecurityVAPTReport)  

---

### [CVE-2025-62168](CVE-2025-62168-monzaviman_CVE-2025-62168.md) 🔴 ✅

**名称:** CVE-2025-62168-Squid-信息泄露  
**类型:** 信息泄露  
**风险:** 高危，可能导致敏感凭据泄露，进而导致未授权访问  
**投毒风险:** 80%  
**发现时间:** 2025-10-23  
**POC仓库:** [CVE-2025-62168](https://github.com/monzaviman/CVE-2025-62168)  

---

### [CVE-2025-53072](CVE-2025-53072-rxerium_CVE-2025-53072-CVE-2025-62481.md) 🔴 ✅

**名称:** CVE-2025-53072 & CVE-2025-62481 - Oracle Marketing Takeover  
**类型:** 未授权远程代码执行/信息泄露  
**风险:** 高危，可导致完全控制Oracle Marketing  
**投毒风险:** 10%  
**发现时间:** 2025-10-23  
**POC仓库:** [CVE-2025-53072-CVE-2025-62481](https://github.com/rxerium/CVE-2025-53072-CVE-2025-62481)  

---

### [CVE-2025-53072](CVE-2025-53072-RedFoxNxploits_CVE-2025-53072.md)  ✅

**名称:** CVE-2025-53072 - Oracle E-Business Suite Marketing RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 严重，可导致完全系统接管  
**投毒风险:** 60%  
**发现时间:** 2025-10-23  
**POC仓库:** [CVE-2025-53072](https://github.com/RedFoxNxploits/CVE-2025-53072)  

---

### [CVE-2023-2745](CVE-2023-2745-fofovicfof-ai_cve-2023-2745.md) 🟡 ✅

**名称:** CVE-2023-2745-WordPress-目录遍历  
**类型:** 目录遍历  
**风险:** 中危，可能导致敏感信息泄露或XSS攻击  
**投毒风险:** 0%  
**发现时间:** 2025-10-23  
**POC仓库:** [cve-2023-2745](https://github.com/fofovicfof-ai/cve-2023-2745)  

---

### [CVE-2025-6758](CVE-2025-6758-Nxploited_CVE-2025-6758.md)  ✅

**名称:** CVE-2025-6758 - Real Spaces WordPress Theme 未授权提权  
**类型:** 权限提升  
**风险:** 严重，允许未授权用户注册为管理员  
**投毒风险:** 5%  
**发现时间:** 2025-10-23  
**POC仓库:** [CVE-2025-6758](https://github.com/Nxploited/CVE-2025-6758)  

---

### [CVE-2025-54782](CVE-2025-54782-vxaretra_CVE-2025-54782.md) 🔴 ✅

**名称:** CVE-2025-54782-@nestjs/devtools-integration-RCE  
**类型:** 远程代码执行(RCE)  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-10-23  
**POC仓库:** [CVE-2025-54782](https://github.com/vxaretra/CVE-2025-54782)  

---

### [CVE-2022-0001](CVE-2022-0001-Sabecomoeh_CVE-2022-0001.md) 🟡 ✅

**名称:** CVE-2022-0001-Intel Processors-信息泄露  
**类型:** 信息泄露  
**风险:** 中危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-10-23  
**POC仓库:** [CVE-2022-0001](https://github.com/Sabecomoeh/CVE-2022-0001)  

---

### [CVE-2025-60791](CVE-2025-60791-Smarttfoxx_CVE-2025-60791.md) 🟡 ✅

**名称:** CVE-2025-60791: Easywork Enterprise 2.1.3.354 Cleartext Storage of Sensitive Information in Memory  
**类型:** 敏感信息明文存储  
**风险:** 中危，可能导致未授权使用软件  
**投毒风险:** 0%  
**发现时间:** 2025-10-23  
**POC仓库:** [CVE-2025-60791](https://github.com/Smarttfoxx/CVE-2025-60791)  

---

### [CVE-2019-7164](CVE-2019-7164-stuxbench_mlflow-cve-2019-7164.md) 🔴 ✅

**名称:** CVE-2019-7164-SQLAlchemy-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露和远程代码执行  
**投毒风险:** 20%  
**发现时间:** 2025-10-23  
**POC仓库:** [mlflow-cve-2019-7164](https://github.com/stuxbench/mlflow-cve-2019-7164)  

---

### [CVE-2024-49138](CVE-2024-49138-codetronik_CVE-2024-49138.md) 🔴 ✅

**名称:** CVE-2024-49138  
**类型:** 权限提升  
**风险:** 高危，本地权限提升  
**投毒风险:** 10%  
**发现时间:** 2025-10-23  
**POC仓库:** [CVE-2024-49138](https://github.com/codetronik/CVE-2024-49138)  

---

### [CVE-2023-45612](CVE-2023-45612-aecelen_ktor-xxe-poc.md) 🔴 ✅

**名称:** CVE-2023-45612-Ktor-XXE  
**类型:** XXE  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-10-23  
**POC仓库:** [ktor-xxe-poc](https://github.com/aecelen/ktor-xxe-poc)  

---

### [CVE-2023-45612](CVE-2023-45612-clemfavre_cve-2023-45612_exploit.md) 🔴 ✅

**名称:** CVE-2023-45612-Ktor-XXE  
**类型:** XXE (XML External Entity)  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 5%  
**发现时间:** 2025-10-23  
**POC仓库:** [cve-2023-45612_exploit](https://github.com/clemfavre/cve-2023-45612_exploit)  

---

### [CVE-2021-3493](CVE-2021-3493-fei9747_CVE-2021-3493.md) 🔴 ✅

**名称:** CVE-2021-3493 Ubuntu OverlayFS 本地提权  
**类型:** 本地提权  
**风险:** 高危，攻击者可利用此漏洞获取 root 权限  
**投毒风险:** 5%  
**发现时间:** 2025-10-23  
**POC仓库:** [CVE-2021-3493](https://github.com/fei9747/CVE-2021-3493)  

---

### [CVE-2021-3493](CVE-2021-3493-smallkill_CVE-2021-3493.md) 🔴 ✅

**名称:** CVE-2021-3493-Ubuntu OverlayFS 本地权限提升  
**类型:** 本地权限提升  
**风险:** 高危，可使低权限用户获得 root 权限  
**投毒风险:** 0%  
**发现时间:** 2025-10-23  
**POC仓库:** [CVE-2021-3493](https://github.com/smallkill/CVE-2021-3493)  

---

### [CVE-2021-3493](CVE-2021-3493-cyberx-1_OverlayFS-CVE-2021-3493.md) 🔴 ✅

**名称:** CVE-2021-3493-Ubuntu OverlayFS 本地提权  
**类型:** 本地提权  
**风险:** 高危，可从普通用户提权至root  
**投毒风险:** 10%  
**发现时间:** 2025-10-23  
**POC仓库:** [OverlayFS-CVE-2021-3493](https://github.com/cyberx-1/OverlayFS-CVE-2021-3493)  

---

### [CVE-2024-7387](CVE-2024-7387-tevelsho_cve-2024-7387.md) 🔴 ✅

**名称:** CVE-2024-7387-Openshift/builder-命令注入  
**类型:** 命令注入  
**风险:** 高危，可能导致权限提升和节点接管  
**投毒风险:** 10%  
**发现时间:** 2025-10-22  
**POC仓库:** [cve-2024-7387](https://github.com/tevelsho/cve-2024-7387)  

---

### [CVE-2025-57517](CVE-2025-57517-0xsamurai_CVE-2025-57517.md) 🔴 ✅

**名称:** WonderCMS 3.5.0 存储型跨站脚本漏洞  
**类型:** 存储型跨站脚本 (Stored XSS)  
**风险:** 高危，可导致会话劫持、凭据窃取以及其他恶意行为  
**投毒风险:** 10%  
**发现时间:** 2025-10-22  
**POC仓库:** [CVE-2025-57517](https://github.com/0xsamurai/CVE-2025-57517)  

---

### [CVE-2025-49002](CVE-2025-49002-jiuzui129-arch_CVE-2025-49002.md) 🔴 ✅

**名称:** CVE-2025-49002-DataEase-H2数据库远程代码执行绕过  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-10-22  
**POC仓库:** [CVE-2025-49002](https://github.com/jiuzui129-arch/CVE-2025-49002)  

---

### [CVE-2025-56799](CVE-2025-56799-shinyColumn_CVE-2025-56799.md) 🟡 ✅

**名称:** CVE-2025-56799-Reolink桌面应用-命令注入  
**类型:** 命令注入  
**风险:** 中危，可能导致命令执行  
**投毒风险:** 10%  
**发现时间:** 2025-10-22  
**POC仓库:** [CVE-2025-56799](https://github.com/shinyColumn/CVE-2025-56799)  

---

### [CVE-2025-23048](CVE-2025-23048-absholi7ly_CVE-2025-23048-POC.md) 🔴 ✅

**名称:** CVE-2025-23048: Apache mod_ssl TLS 1.3 Session Resumption Client Certificate Bypass  
**类型:** 访问控制绕过  
**风险:** 高危，可能导致未经授权的访问敏感资源  
**投毒风险:** 10%  
**发现时间:** 2025-10-22  
**POC仓库:** [CVE-2025-23048-POC](https://github.com/absholi7ly/CVE-2025-23048-POC)  

---

### [CVE-2023-32571](CVE-2023-32571-vert16x_CVE-2023-32571-POC.md) 🔴 ✅

**名称:** CVE-2023-32571-Dynamic Linq RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，允许攻击者执行任意代码和命令  
**投毒风险:** 10%  
**发现时间:** 2025-10-21  
**POC仓库:** [CVE-2023-32571-POC](https://github.com/vert16x/CVE-2023-32571-POC)  

---

### [CVE-2023-32571](CVE-2023-32571-Tris0n_CVE-2023-32571-POC.md) 🔴 ✅

**名称:** CVE-2023-32571-Dynamic Linq RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，允许攻击者执行任意代码和命令。  
**投毒风险:** 10%  
**发现时间:** 2025-10-21  
**POC仓库:** [CVE-2023-32571-POC](https://github.com/Tris0n/CVE-2023-32571-POC)  

---

### [CVE-2023-32571](CVE-2023-32571-SecTex_CVE-2023-32571.md) 🔴 ✅

**名称:** CVE-2023-32571-System.Linq.Dynamic.Core-RCE  
**类型:** 远程代码执行  
**风险:** 高危，允许攻击者执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-10-21  
**POC仓库:** [CVE-2023-32571](https://github.com/SecTex/CVE-2023-32571)  

---

### [CVE-2025-12654](CVE-2025-12654-Tarimaow_Anydesk-Exploit-CVE-2025-12654-RCE-Builder.md) 🔴 ✅

**名称:** AnyDesk Exploit  
**类型:** 远程代码执行 (RCE), DLL劫持, 身份验证绕过, DLL注入, 权限管理不当, 数据泄露, 网络扫描  
**风险:** 高危，可能导致远程代码执行、数据泄露、权限提升和系统控制  
**投毒风险:** 60%  
**发现时间:** 2025-10-21  
**POC仓库:** [Anydesk-Exploit-CVE-2025-12654-RCE-Builder](https://github.com/Tarimaow/Anydesk-Exploit-CVE-2025-12654-RCE-Builder)  

---

### [CVE-2024-9348](CVE-2024-9348-Nimisha17_CVE-2024-9348-poc.md) 🔴 

**名称:** CVE-2024-9348-Docker Desktop RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可导致完全系统控制  
**投毒风险:** 0%  
**发现时间:** 2025-10-21  
**POC仓库:** [CVE-2024-9348-poc](https://github.com/Nimisha17/CVE-2024-9348-poc)  

---

### [CVE-2017-7679](CVE-2017-7679-Al-Lord0x_CVE-2017-7679.md) 🟡 ✅

**名称:** CVE-2017-7679 Apache mod_mime 缓冲区溢出  
**类型:** 缓冲区溢出  
**风险:** 中危，可能导致信息泄露或拒绝服务  
**投毒风险:** 5%  
**发现时间:** 2025-10-21  
**POC仓库:** [CVE-2017-7679](https://github.com/Al-Lord0x/CVE-2017-7679)  

---

### [CVE-2025-8088](CVE-2025-8088-kaucent_CVE-2025-8088.md) 🔴 ✅

**名称:** CVE-2025-8088 WinRAR 路径遍历漏洞  
**类型:** 路径遍历  
**风险:** 高危，可能导致任意代码执行  
**投毒风险:** 75%  
**发现时间:** 2025-10-21  
**POC仓库:** [CVE-2025-8088](https://github.com/kaucent/CVE-2025-8088)  

---

### [CVE-2025-31161](CVE-2025-31161-cesarbtakeda_CVE-2025-31161.md)  ✅

**名称:** CVE-2025-31161-CrushFTP-Authentication Bypass  
**类型:** 身份验证绕过  
**风险:** 严重，可能导致完全系统控制  
**投毒风险:** 5%  
**发现时间:** 2025-10-21  
**POC仓库:** [CVE-2025-31161](https://github.com/cesarbtakeda/CVE-2025-31161)  

---

### [CVE-2025-24203](CVE-2025-24203-pxx917144686_iDevice_ZH.md) 🟡 ✅

**名称:** CVE-2025-24203-macOS/iPadOS 文件系统修改漏洞  
**类型:** 文件系统修改  
**风险:** 中危，可能导致本地权限提升和文件系统破坏  
**投毒风险:** 10%  
**发现时间:** 2025-10-21  
**POC仓库:** [iDevice_ZH](https://github.com/pxx917144686/iDevice_ZH)  

---

### [CVE-2020-35590](CVE-2020-35590-N4nj0_CVE-2020-35590.md) 🟡 ✅

**名称:** CVE-2020-35590-Limit Login Attempts Reloaded-登录限制绕过  
**类型:** 速率限制绕过  
**风险:** 中危，可能导致暴力破解攻击  
**投毒风险:** 10%  
**发现时间:** 2025-10-21  
**POC仓库:** [CVE-2020-35590](https://github.com/N4nj0/CVE-2020-35590)  

---

### [CVE-2025-20282](CVE-2025-20282-skadevare_CiscoISE-CVE-2025-20282-POC.md)  ✅

**名称:** CVE-2025-20282-Cisco ISE API未授权远程代码执行  
**类型:** 远程代码执行  
**风险:** 严重，可能导致完全系统控制  
**投毒风险:** 10%  
**发现时间:** 2025-10-21  
**POC仓库:** [CiscoISE-CVE-2025-20282-POC](https://github.com/skadevare/CiscoISE-CVE-2025-20282-POC)  

---

### [CVE-2025-44228](CVE-2025-44228-Kartiowmn_Office-Exploit-Cve2025-Xml-Doc-Docx-Rce-Builder-Fud.md) 🔴 ✅

**名称:** Office Macr Exploit v1.0.0  
**类型:** Office宏漏洞  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 80%  
**发现时间:** 2025-10-21  
**POC仓库:** [Office-Exploit-Cve2025-Xml-Doc-Docx-Rce-Builder-Fud](https://github.com/Kartiowmn/Office-Exploit-Cve2025-Xml-Doc-Docx-Rce-Builder-Fud)  

---

### [CVE-2025-44228](CVE-2025-44228-Kartiowmn_Lnk-Exploit-FileBinder-Certificate-Spoofer-Reg-Doc-Cve-Rce.md) 🔴 ✅

**名称:** LNK Exploit  
**类型:** LNK文件利用  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 70%  
**发现时间:** 2025-10-21  
**POC仓库:** [Lnk-Exploit-FileBinder-Certificate-Spoofer-Reg-Doc-Cve-Rce](https://github.com/Kartiowmn/Lnk-Exploit-FileBinder-Certificate-Spoofer-Reg-Doc-Cve-Rce)  

---

### [CVE-2025-49002](CVE-2025-49002-Feng-Huang-0520_DataEase_Postgresql_JDBC_Bypass-CVE-2025-49002.md) 🔴 ✅

**名称:** CVE-2025-49002-DataEase-RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-10-21  
**POC仓库:** [DataEase_Postgresql_JDBC_Bypass-CVE-2025-49002](https://github.com/Feng-Huang-0520/DataEase_Postgresql_JDBC_Bypass-CVE-2025-49002)  

---

### [CVE-2025-7850](CVE-2025-7850-ByteHawkSec_CVE-2025-7850-POC.md) 🔴 ✅

**名称:** CVE-2025-7850 - Omada Gateway OS Command Injection  
**类型:** OS Command Injection  
**风险:** 高危，可能导致系统完全控制、数据泄露和拒绝服务  
**投毒风险:** 10%  
**发现时间:** 2025-10-21  
**POC仓库:** [CVE-2025-7850-POC](https://github.com/ByteHawkSec/CVE-2025-7850-POC)  

---

### [CVE-2025-8088](CVE-2025-8088-papcaii2004_CVE-2025-8088-WinRAR-builder.md) 🔴 ✅

**名称:** CVE-2025-8088-WinRAR 路径遍历漏洞  
**类型:** 路径遍历  
**风险:** 高危，允许攻击者通过构造恶意压缩文件执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-10-21  
**POC仓库:** [CVE-2025-8088-WinRAR-builder](https://github.com/papcaii2004/CVE-2025-8088-WinRAR-builder)  

---

### [CVE-2025-11391](CVE-2025-11391-aritlhq_CVE-2025-11391.md) 🔴 ✅

**名称:** CVE-2025-11391 - PPOM – Product Addons & Custom Fields for WooCommerce - Unauthenticated Arbitrary File Upload  
**类型:** 任意文件上传  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-10-20  
**POC仓库:** [CVE-2025-11391](https://github.com/aritlhq/CVE-2025-11391)  

---

### [CVE-2025-9744](CVE-2025-9744-godfatherofexps_CVE-2025-9744-PoC.md) 🔴 ✅

**名称:** CVE-2025-9744-Online Loan Management System-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露和权限提升  
**投毒风险:** 10%  
**发现时间:** 2025-10-20  
**POC仓库:** [CVE-2025-9744-PoC](https://github.com/godfatherofexps/CVE-2025-9744-PoC)  

---

### [CVE-2025-11391](CVE-2025-11391-aritlhq_CVE-2025-11391.md) 🔴 ✅

**名称:** CVE-2025-11391-PPOM-Unauthenticated Arbitrary File Upload  
**类型:** Arbitrary File Upload  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-10-20  
**POC仓库:** [CVE-2025-11391](https://github.com/aritlhq/CVE-2025-11391)  

---

### [CVE-2025-10041](CVE-2025-10041-DExplo1ted_CVE-2025-10041-POC.md)  ✅

**名称:** CVE-2025-10041 - Flex QR Code Generator <= 1.2.5 - Unauthenticated Arbitrary File Upload  
**类型:** 任意文件上传  
**风险:** 严重，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-10-20  
**POC仓库:** [CVE-2025-10041-POC](https://github.com/DExplo1ted/CVE-2025-10041-POC)  

---

### [CVE-2025-59230](CVE-2025-59230-moegameka_CVE-2025-59230.md) 🔴 ✅

**名称:** CVE-2025-59230 - Windows Remote Access Connection Manager 权限提升  
**类型:** 权限提升  
**风险:** 高危，本地权限提升至 SYSTEM  
**投毒风险:** 10%  
**发现时间:** 2025-10-20  
**POC仓库:** [CVE-2025-59230](https://github.com/moegameka/CVE-2025-59230)  

---

### [CVE-2025-59287](CVE-2025-59287-keeganparr1_CVE-2025-59287-hawktrace.md) 🔴 ✅

**名称:** CVE-2025-59287-Windows Server Update Service (WSUS) Remote Code Execution Vulnerability  
**类型:** 反序列化漏洞  
**风险:** 高危，远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-10-20  
**POC仓库:** [CVE-2025-59287-hawktrace](https://github.com/keeganparr1/CVE-2025-59287-hawktrace)  

---

### [CVE-2015-1635](CVE-2015-1635-Zx7ffa4512-Python_Project-CVE-2015-1635.md) 🔴 ✅

**名称:** CVE-2015-1635  
**类型:** 远程代码执行  
**风险:** 高危，允许远程攻击者在系统帐户的上下文中执行任意代码  
**投毒风险:** 5%  
**发现时间:** 2025-10-20  
**POC仓库:** [Project-CVE-2015-1635](https://github.com/Zx7ffa4512-Python/Project-CVE-2015-1635)  

---

### [CVE-2015-1635](CVE-2015-1635-xPaw_HTTPsys.md) 🔴 ✅

**名称:** CVE-2015-1635-HTTP.sys远程代码执行漏洞  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-10-20  
**POC仓库:** [HTTPsys](https://github.com/xPaw/HTTPsys)  

---

### [CVE-2015-1635](CVE-2015-1635-wiredaem0n_chk-ms15-034.md) 🔴 ✅

**名称:** CVE-2015-1635 (MS15-034) HTTP.sys Remote Code Execution Vulnerability  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致远程代码执行和拒绝服务  
**投毒风险:** 0%  
**发现时间:** 2025-10-20  
**POC仓库:** [chk-ms15-034](https://github.com/wiredaem0n/chk-ms15-034)  

---

### [CVE-2015-1635](CVE-2015-1635-h3x0v3rl0rd_CVE-2015-1635-POC.md) 🔴 ✅

**名称:** CVE-2015-1635 - HTTP.sys 远程代码执行漏洞  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-10-20  
**POC仓库:** [CVE-2015-1635-POC](https://github.com/h3x0v3rl0rd/CVE-2015-1635-POC)  

---

### [CVE-2017-10003](CVE-2017-10003-Jelc0Doesbruf_CVE-2017-1000353.md) 🟡 

**名称:** CVE-2017-10003-Solaris-Network Services Library  
**类型:** 权限提升/DoS  
**风险:** 中危，可能导致敏感数据泄露和部分拒绝服务  
**投毒风险:** 95%  
**发现时间:** 2025-10-20  
**POC仓库:** [CVE-2017-1000353](https://github.com/Jelc0Doesbruf/CVE-2017-1000353)  

---

### [CVE-2015-1635](CVE-2015-1635-u0pattern_Remove-IIS-RIIS.md) 🔴 ✅

**名称:** CVE-2015-1635 - HTTP.sys 远程代码执行漏洞  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，允许远程攻击者执行任意代码  
**投毒风险:** 0%  
**发现时间:** 2025-10-20  
**POC仓库:** [Remove-IIS-RIIS](https://github.com/u0pattern/Remove-IIS-RIIS)  

---

### [CVE-2015-1635](CVE-2015-1635-bongbongco_MS15-034.md) 🔴 ✅

**名称:** CVE-2015-1635 (MS15-034) - HTTP.sys 远程代码执行漏洞  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致远程代码执行或拒绝服务 (蓝屏)  
**投毒风险:** 10%  
**发现时间:** 2025-10-20  
**POC仓库:** [MS15-034](https://github.com/bongbongco/MS15-034)  

---

### [CVE-2015-1635](CVE-2015-1635-technion_erlvulnscan.md) 🔴 ✅

**名称:** CVE-2015-1635  
**类型:** 远程代码执行  
**风险:** 高危，远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-10-20  
**POC仓库:** [erlvulnscan](https://github.com/technion/erlvulnscan)  

---

### [CVE-2015-1635](CVE-2015-1635-aedoo_CVE-2015-1635-POC.md) 🔴 ✅

**名称:** CVE-2015-1635 HTTP.sys 远程代码执行漏洞  
**类型:** 远程代码执行  
**风险:** 高危，可能导致系统完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-10-20  
**POC仓库:** [CVE-2015-1635-POC](https://github.com/aedoo/CVE-2015-1635-POC)  

---

### [CVE-2015-1635](CVE-2015-1635-h3x0v3rl0rd_CVE-2015-1635.md) 🔴 ✅

**名称:** CVE-2015-1635-HTTP.sys远程代码执行漏洞  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行和系统崩溃  
**投毒风险:** 10%  
**发现时间:** 2025-10-20  
**POC仓库:** [CVE-2015-1635](https://github.com/h3x0v3rl0rd/CVE-2015-1635)  

---

### [CVE-2015-1635](CVE-2015-1635-w01ke_CVE-2015-1635-POC.md) 🔴 ✅

**名称:** CVE-2015-1635 HTTP.sys 远程代码执行漏洞  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-10-20  
**POC仓库:** [CVE-2015-1635-POC](https://github.com/w01ke/CVE-2015-1635-POC)  

---

### [CVE-2015-1635](CVE-2015-1635-SkinAir_ms15-034-Scan.md) 🔴 ✅

**名称:** CVE-2015-1635-HTTP.sys远程代码执行漏洞  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-10-20  
**POC仓库:** [ms15-034-Scan](https://github.com/SkinAir/ms15-034-Scan)  

---

### [CVE-2015-1635](CVE-2015-1635-Cappricio-Securities_CVE-2015-1635.md) 🔴 ✅

**名称:** CVE-2015-1635 (HTTP.sys Remote Code Execution)  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致系统完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-10-20  
**POC仓库:** [CVE-2015-1635](https://github.com/Cappricio-Securities/CVE-2015-1635)  

---

### [CVE-2015-1635](CVE-2015-1635-moeinmiadi_CVE-2015-1635_PoC.md) 🔴 ✅

**名称:** CVE-2015-1635 HTTP.sys 远程代码执行漏洞  
**类型:** 远程代码执行  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-10-20  
**POC仓库:** [CVE-2015-1635_PoC](https://github.com/moeinmiadi/CVE-2015-1635_PoC)  

---

### [CVE-2025-32433](CVE-2025-32433-toshithh_CVE-2025-32433.md)  ✅

**名称:** CVE-2025-32433-Erlang/OTP-SSH-Pre-Authentication RCE  
**类型:** 远程代码执行  
**风险:** 严重，未经身份验证的远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-10-20  
**POC仓库:** [CVE-2025-32433](https://github.com/toshithh/CVE-2025-32433)  

---

### [CVE-2025-30208](CVE-2025-30208-Lusensec_CVE-2025-30208.md) 🟡 ✅

**名称:** CVE-2025-30208 - Vite 任意文件读取  
**类型:** 任意文件读取  
**风险:** 中危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-10-20  
**POC仓库:** [CVE-2025-30208](https://github.com/Lusensec/CVE-2025-30208)  

---

### [CVE-2025-54874](CVE-2025-54874-cyhe50_cve-2025-54874-poc.md) 🟡 ✅

**名称:** CVE-2025-54874-OpenJPEG-堆内存写溢出  
**类型:** 堆内存写溢出  
**风险:** 中危，可能导致拒绝服务或信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-10-20  
**POC仓库:** [cve-2025-54874-poc](https://github.com/cyhe50/cve-2025-54874-poc)  

---

### [CVE-2025-10294](CVE-2025-10294-RedFoxNxploits_CVE-2025-10294-Poc.md) 🔴 

**名称:** CVE-2025-10294-OwnID Passwordless Login Authentication Bypass  
**类型:** Authentication Bypass  
**风险:** Critical, 可能导致任意用户登录，包括管理员  
**投毒风险:** 0%  
**发现时间:** 2025-10-19  
**POC仓库:** [CVE-2025-10294-Poc](https://github.com/RedFoxNxploits/CVE-2025-10294-Poc)  

---

### [CVE-2025-59295](CVE-2025-59295-usjnx72726w_CVE-2025-59295.md) 🔴 

**名称:** CVE-2025-59295  
**类型:** Windows URL Parsing Remote Code Execution  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-10-19  
**POC仓库:** [CVE-2025-59295](https://github.com/usjnx72726w/CVE-2025-59295)  

---

### [CVE-2023-28121](CVE-2023-28121-0axz-tools_CVE-2023-28121.md) 🔴 ✅

**名称:** CVE-2023-28121 - WooCommerce Payments 未授权提权漏洞  
**类型:** 权限提升  
**风险:** 高危，允许未经身份验证的攻击者以管理员身份发送请求，从而获得对站点的完全控制。  
**投毒风险:** 10%  
**发现时间:** 2025-10-19  
**POC仓库:** [CVE-2023-28121](https://github.com/0axz-tools/CVE-2023-28121)  

---

### [CVE-2025-1094](CVE-2025-1094-PinkArmor_CVE-2025-1094-Lab-Setup.md) 🔴 ✅

**名称:** CVE-2025-1094-PostgreSQL-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-10-19  
**POC仓库:** [CVE-2025-1094-Lab-Setup](https://github.com/PinkArmor/CVE-2025-1094-Lab-Setup)  

---

### [CVE-2025-11579](CVE-2025-11579-shinigami-777_PoC_CVE-2025-11579.md) 🟡 ✅

**名称:** CVE-2025-11579-rardecode-DoS  
**类型:** 拒绝服务 (DoS)  
**风险:** 中危，导致服务不可用  
**投毒风险:** 0%  
**发现时间:** 2025-10-19  
**POC仓库:** [PoC_CVE-2025-11579](https://github.com/shinigami-777/PoC_CVE-2025-11579)  

---

### [CVE-2025-10230](CVE-2025-10230-dptsec_CVE-2025-10230.md) 🔴 ✅

**名称:** CVE-2025-10230 - Samba WINS Hook Command Injection  
**类型:** 命令注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-10-19  
**POC仓库:** [CVE-2025-10230](https://github.com/dptsec/CVE-2025-10230)  

---

### [CVE-2025-32463](CVE-2025-32463-robbin0919_CVE-2025-32463.md)  ✅

**名称:** CVE-2025-32463-Sudo-本地权限提升  
**类型:** 本地权限提升  
**风险:** 严重，可获取Root权限  
**投毒风险:** 10%  
**发现时间:** 2025-10-19  
**POC仓库:** [CVE-2025-32463](https://github.com/robbin0919/CVE-2025-32463)  

---

### [CVE-2025-39965](CVE-2025-39965-Shreyas-Penkar_CVE-2025-39965.md) 🔴 

**名称:** CVE-2025-39965-Linux Kernel-XFRM UAF  
**类型:** UAF (Use-After-Free)  
**风险:** 高危，可能导致内核崩溃或权限提升  
**投毒风险:** 0%  
**发现时间:** 2025-10-19  
**POC仓库:** [CVE-2025-39965](https://github.com/Shreyas-Penkar/CVE-2025-39965)  

---

### [CVE-2025-59285](CVE-2025-59285-allinsthon_CVE-2025-59285.md) 🔴 

**名称:** CVE-2025-59285 - Azure Monitor Agent 提权漏洞  
**类型:** 反序列化漏洞导致权限提升  
**风险:** 高危，本地权限提升  
**投毒风险:** 5%  
**发现时间:** 2025-10-19  
**POC仓库:** [CVE-2025-59285](https://github.com/allinsthon/CVE-2025-59285)  

---

### [CVE-2019-9053](CVE-2019-9053-CaelumIsMe_CVE-2019-9053-POC.md) 🔴 ✅

**名称:** CVE-2019-9053-CMS Made Simple-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露，权限提升  
**投毒风险:** 1%  
**发现时间:** 2025-10-19  
**POC仓库:** [CVE-2019-9053-POC](https://github.com/CaelumIsMe/CVE-2019-9053-POC)  

---

### [CVE-2025-32433](CVE-2025-32433-Batman529_PoC-CVE-2025-32433.md) 🔴 ✅

**名称:** CVE-2025-32433-Erlang/OTP SSH 远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，未经身份验证的远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-10-19  
**POC仓库:** [PoC-CVE-2025-32433](https://github.com/Batman529/PoC-CVE-2025-32433)  

---

### [CVE-2016-3627](CVE-2016-3627-Oneton429_CVE-2016-3627.md) 🔴 ✅

**名称:** CVE-2016-3627-libxml2-DoS  
**类型:** 拒绝服务（DoS）  
**风险:** 高危，导致应用崩溃  
**投毒风险:** 0%  
**发现时间:** 2025-10-19  
**POC仓库:** [CVE-2016-3627](https://github.com/Oneton429/CVE-2016-3627)  

---

### [CVE-2025-61884](CVE-2025-61884-shinyhunterz_CVE-2025-61884-61882.md) 🔴 ✅

**名称:** CVE-2025-61884-Oracle Configurator-未授权数据访问  
**类型:** 未授权数据访问  
**风险:** 高危，可能导致关键数据泄露或完全访问Oracle Configurator可访问的所有数据  
**投毒风险:** 95%  
**发现时间:** 2025-10-19  
**POC仓库:** [CVE-2025-61884-61882](https://github.com/shinyhunterz/CVE-2025-61884-61882)  

---

### [CVE-2025-55315](CVE-2025-55315-7huukdlnkjkjba_CVE-2025-55315-.md)  ✅

**名称:** CVE-2025-55315-ASP.NET Core-HTTP请求走私  
**类型:** HTTP请求走私  
**风险:** 严重，可能导致信息泄露、数据篡改、拒绝服务、权限提升、SSRF、绕过CSRF检查和执行注入攻击  
**投毒风险:** 10%  
**发现时间:** 2025-10-19  
**POC仓库:** [CVE-2025-55315-](https://github.com/7huukdlnkjkjba/CVE-2025-55315-)  

---

### [CVE-2025-25257](CVE-2025-25257-silentexploitexe_CVE-2025-25257.md)  ✅

**名称:** CVE-2025-25257-FortiWeb-SQL注入  
**类型:** SQL注入  
**风险:** 严重，可能导致未经授权的SQL代码执行和命令执行  
**投毒风险:** 80%  
**发现时间:** 2025-10-19  
**POC仓库:** [CVE-2025-25257](https://github.com/silentexploitexe/CVE-2025-25257)  

---

### [CVE-2025-56800](CVE-2025-56800-shinyColumn_CVE-2025-56800.md) 🔴 ✅

**名称:** CVE-2025-56800-Reolink Desktop Application-本地认证绕过  
**类型:** 本地认证绕过  
**风险:** 高危，允许本地攻击者完全访问应用程序界面和设置  
**投毒风险:** 0%  
**发现时间:** 2025-10-18  
**POC仓库:** [CVE-2025-56800](https://github.com/shinyColumn/CVE-2025-56800)  

---

### [CVE-2025-27591](CVE-2025-27591-krn966_CVE-2025-27591.md) 🔴 ✅

**名称:** CVE-2025-27591 - Below Privilege Escalation  
**类型:** 权限提升  
**风险:** 高危，本地权限提升至root  
**投毒风险:** 0%  
**发现时间:** 2025-10-18  
**POC仓库:** [CVE-2025-27591](https://github.com/krn966/CVE-2025-27591)  

---

### [CVE-2025-56802](CVE-2025-56802-shinyColumn_CVE-2025-56802.md) 🔴 ✅

**名称:** CVE-2025-56802-Reolink Desktop Application-AES-CFB Key Generation Vulnerability  
**类型:** AES-CFB密钥生成与管理漏洞  
**风险:** 高危，可能导致数据泄露、权限提升甚至远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-10-18  
**POC仓库:** [CVE-2025-56802](https://github.com/shinyColumn/CVE-2025-56802)  

---

### [CVE-2025-56801](CVE-2025-56801-shinyColumn_CVE-2025-56801.md) 🟡 ✅

**名称:** CVE-2025-56801-Reolink Desktop Application-AES-CFB IV Generation Vulnerability  
**类型:** AES-CFB IV Generation Vulnerability  
**风险:** 中危，可能导致敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-10-18  
**POC仓库:** [CVE-2025-56801](https://github.com/shinyColumn/CVE-2025-56801)  

---

### [CVE-2024-11392](CVE-2024-11392-stuxbench_vllm-cve-2024-11392.md) 🔴 ✅

**名称:** CVE-2024-11392-HuggingFaceTransformers-反序列化RCE  
**类型:** 反序列化漏洞  
**风险:** 高危，远程代码执行  
**投毒风险:** 20%  
**发现时间:** 2025-10-18  
**POC仓库:** [vllm-cve-2024-11392](https://github.com/stuxbench/vllm-cve-2024-11392)  

---

### [CVE-2024-11392](CVE-2024-11392-Piyush-Bhor_CVE-2024-11392.md) 🔴 ✅

**名称:** CVE-2024-11392-Hugging Face Transformers MobileViTV2反序列化远程代码执行漏洞  
**类型:** 反序列化  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-10-18  
**POC仓库:** [CVE-2024-11392](https://github.com/Piyush-Bhor/CVE-2024-11392)  

---

### [CVE-2024-27198](CVE-2024-27198-Chocapikk_CVE-2024-27198.md) 🔴 ✅

**名称:** CVE-2024-27198-JetBrains TeamCity Authentication Bypass  
**类型:** 身份验证绕过  
**风险:** 高危，允许未授权用户执行管理员操作  
**投毒风险:** 10%  
**发现时间:** 2025-10-18  
**POC仓库:** [CVE-2024-27198](https://github.com/Chocapikk/CVE-2024-27198)  

---

### [CVE-2024-27198](CVE-2024-27198-passwa11_CVE-2024-27198-RCE.md) 🔴 ✅

**名称:** CVE-2024-27198-JetBrains TeamCity 认证绕过漏洞  
**类型:** 认证绕过  
**风险:** 高危，允许未授权用户执行管理操作  
**投毒风险:** 0%  
**发现时间:** 2025-10-18  
**POC仓库:** [CVE-2024-27198-RCE](https://github.com/passwa11/CVE-2024-27198-RCE)  

---

### [CVE-2024-27198](CVE-2024-27198-CharonDefalt_CVE-2024-27198-RCE.md) 🔴 ✅

**名称:** CVE-2024-27198-JetBrains TeamCity Authentication Bypass & RCE  
**类型:** 身份验证绕过和远程代码执行  
**风险:** 高危，未经授权的管理员访问和远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-10-18  
**POC仓库:** [CVE-2024-27198-RCE](https://github.com/CharonDefalt/CVE-2024-27198-RCE)  

---

### [CVE-2024-27198](CVE-2024-27198-K3ysTr0K3R_CVE-2024-27198-EXPLOIT.md) 🔴 ✅

**名称:** CVE-2024-27198-JetBrains-TeamCity-身份验证绕过  
**类型:** 身份验证绕过  
**风险:** 极高危，可导致未授权的管理员权限获取和远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-10-18  
**POC仓库:** [CVE-2024-27198-EXPLOIT](https://github.com/K3ysTr0K3R/CVE-2024-27198-EXPLOIT)  

---

### [CVE-2024-27198](CVE-2024-27198-W01fh4cker_CVE-2024-27198-RCE.md) 🔴 ✅

**名称:** CVE-2024-27198-TeamCity 身份验证绕过 RCE  
**类型:** 身份验证绕过导致远程代码执行  
**风险:** 高危，允许未经身份验证的攻击者执行任意管理操作和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-10-18  
**POC仓库:** [CVE-2024-27198-RCE](https://github.com/W01fh4cker/CVE-2024-27198-RCE)  

---

### [CVE-2024-27198](CVE-2024-27198-Shimon03_Explora-o-RCE-n-o-autenticado-JetBrains-TeamCity-CVE-2024-27198-.md) 🔴 ✅

**名称:** CVE-2024-27198 - JetBrains TeamCity 身份验证绕过  
**类型:** 身份验证绕过  
**风险:** 高危，允许未经身份验证的攻击者执行管理员操作  
**投毒风险:** 10%  
**发现时间:** 2025-10-18  
**POC仓库:** [Explora-o-RCE-n-o-autenticado-JetBrains-TeamCity-CVE-2024-27198-](https://github.com/Shimon03/Explora-o-RCE-n-o-autenticado-JetBrains-TeamCity-CVE-2024-27198-)  

---

### [CVE-2024-27198](CVE-2024-27198-HPT-Intern-Task-Submission_CVE-2024-27198.md) 🔴 ✅

**名称:** CVE-2024-27198 TeamCity 身份验证绕过  
**类型:** 身份验证绕过  
**风险:** 高危，允许未授权用户执行管理操作，可能导致数据泄露和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-10-18  
**POC仓库:** [CVE-2024-27198](https://github.com/HPT-Intern-Task-Submission/CVE-2024-27198)  

---

### [CVE-2024-27198](CVE-2024-27198-jrbH4CK_CVE-2024-27198.md) 🔴 ✅

**名称:** CVE-2024-27198 - JetBrains TeamCity Authentication Bypass  
**类型:** 身份验证绕过  
**风险:** 高危，允许攻击者执行管理员操作，包括远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-10-18  
**POC仓库:** [CVE-2024-27198](https://github.com/jrbH4CK/CVE-2024-27198)  

---

### [CVE-2024-27198](CVE-2024-27198-geniuszly_CVE-2024-27198.md)  ✅

**名称:** CVE-2024-27198-JetBrains TeamCity 身份验证绕过  
**类型:** 身份验证绕过  
**风险:** 严重，允许未经身份验证的攻击者执行管理操作  
**投毒风险:** 10%  
**发现时间:** 2025-10-18  
**POC仓库:** [CVE-2024-27198](https://github.com/geniuszly/CVE-2024-27198)  

---

### [CVE-2024-27198](CVE-2024-27198-Cythonic1_CVE-2024-27198_POC.md) 🔴 ✅

**名称:** CVE-2024-27198-JetBrains-TeamCity-身份验证绕过  
**类型:** 身份验证绕过  
**风险:** 高危，允许未经授权的用户执行管理员操作  
**投毒风险:** 5%  
**发现时间:** 2025-10-18  
**POC仓库:** [CVE-2024-27198_POC](https://github.com/Cythonic1/CVE-2024-27198_POC)  

---

### [CVE-2024-27198](CVE-2024-27198-yoryio_CVE-2024-27198.md)  ✅

**名称:** CVE-2024-27198-JetBrainsTeamCity-认证绕过  
**类型:** 认证绕过  
**风险:** 严重，允许未授权用户执行管理员操作  
**投毒风险:** 0%  
**发现时间:** 2025-10-18  
**POC仓库:** [CVE-2024-27198](https://github.com/yoryio/CVE-2024-27198)  

---

### [CVE-2024-27198](CVE-2024-27198-ArtemCyberLab_Project-Exploiting-CVE-2024-27198-RCE-Vulnerability.md)  ✅

**名称:** CVE-2024-27198-TeamCity-认证绕过RCE  
**类型:** 认证绕过RCE  
**风险:** 严重，可能导致完全控制受影响的TeamCity服务器  
**投毒风险:** 0%  
**发现时间:** 2025-10-18  
**POC仓库:** [Project-Exploiting-CVE-2024-27198-RCE-Vulnerability](https://github.com/ArtemCyberLab/Project-Exploiting-CVE-2024-27198-RCE-Vulnerability)  

---

### [CVE-2024-27198](CVE-2024-27198-wall0wW1spr_CVE-2024-27198.md)  ✅

**名称:** CVE-2024-27198-JetBrains TeamCity 身份验证绕过  
**类型:** 身份验证绕过  
**风险:** 严重，允许未授权用户执行管理员操作，可能导致完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-10-18  
**POC仓库:** [CVE-2024-27198](https://github.com/wall0wW1spr/CVE-2024-27198)  

---

### [CVE-2021-27905](CVE-2021-27905-Henry4E36_Solr-SSRF.md) 🔴 ✅

**名称:** CVE-2021-27905-ApacheSolr-SSRF  
**类型:** SSRF  
**风险:** 高危，可能导致服务器端请求伪造，信息泄露和潜在的RCE  
**投毒风险:** 0%  
**发现时间:** 2025-10-18  
**POC仓库:** [Solr-SSRF](https://github.com/Henry4E36/Solr-SSRF)  

---

### [CVE-2021-27905](CVE-2021-27905-W2Ning_Solr-SSRF.md) 🔴 ✅

**名称:** CVE-2021-27905-Apache Solr-SSRF  
**类型:** SSRF  
**风险:** 高危，可能导致服务器敏感信息泄露，内网探测，甚至远程代码执行（结合其他漏洞）  
**投毒风险:** 5%  
**发现时间:** 2025-10-18  
**POC仓库:** [Solr-SSRF](https://github.com/W2Ning/Solr-SSRF)  

---

### [CVE-2021-27905](CVE-2021-27905-murataydemir_CVE-2021-27905.md) 🔴 ✅

**名称:** CVE-2021-27905 Apache Solr ReplicationHandler SSRF  
**类型:** SSRF  
**风险:** 高危，可能导致信息泄露、内网探测等  
**投毒风险:** 10%  
**发现时间:** 2025-10-18  
**POC仓库:** [CVE-2021-27905](https://github.com/murataydemir/CVE-2021-27905)  

---

### [CVE-2021-27905](CVE-2021-27905-pdelteil_CVE-2021-27905.POC.md) 🔴 ✅

**名称:** CVE-2021-27905 Apache Solr SSRF漏洞  
**类型:** SSRF (Server-Side Request Forgery)  
**风险:** 高危，可能导致敏感信息泄露、内网探测、甚至远程代码执行（取决于目标内网环境）  
**投毒风险:** 10%  
**发现时间:** 2025-10-18  
**POC仓库:** [CVE-2021-27905.POC](https://github.com/pdelteil/CVE-2021-27905.POC)  

---

### [CVE-2021-27905](CVE-2021-27905-RIZZZIOM_CVE-2021-27905.md) 🔴 ✅

**名称:** CVE-2021-27905 - Apache Solr SSRF  
**类型:** SSRF (Server-Side Request Forgery)  
**风险:** 高危，可能导致信息泄露、内部服务访问、远程代码执行（取决于内部网络的配置）  
**投毒风险:** 10%  
**发现时间:** 2025-10-18  
**POC仓库:** [CVE-2021-27905](https://github.com/RIZZZIOM/CVE-2021-27905)  

---

### [CVE-2025-33073](CVE-2025-33073-SellMeFish_windows-smb-vulnerability-framework-cve-2025-33073.md) 🔴 ✅

**名称:** CVE-2025-33073-Windows SMB Client Elevation of Privilege  
**类型:** 特权提升  
**风险:** 高危，可能导致权限提升  
**投毒风险:** 20%  
**发现时间:** 2025-10-18  
**POC仓库:** [windows-smb-vulnerability-framework-cve-2025-33073](https://github.com/SellMeFish/windows-smb-vulnerability-framework-cve-2025-33073)  

---

### [CVE-2025-10742](CVE-2025-10742-netspecters_CVE-2025-10742.md) 🔴 ✅

**名称:** CVE-2025-10742 - Truelysell Core Unauthenticated Arbitrary User Password Change  
**类型:** 权限绕过  
**风险:** 高危，可能导致账户接管和系统入侵  
**投毒风险:** 0%  
**发现时间:** 2025-10-17  
**POC仓库:** [CVE-2025-10742](https://github.com/netspecters/CVE-2025-10742)  

---

### [CVE-2024-21754](CVE-2024-21754-hacktidexp_CVE-2024-21754-FORTI-RCE.md) 🟡 ✅

**名称:** CVE-2024-21754-FortiOS/FortiProxy-密码哈希漏洞  
**类型:** 密码哈希算法强度不足  
**风险:** 中危，可能导致敏感信息泄露  
**投毒风险:** 80%  
**发现时间:** 2025-10-17  
**POC仓库:** [CVE-2024-21754-FORTI-RCE](https://github.com/hacktidexp/CVE-2024-21754-FORTI-RCE)  

---

### [CVE-2025-55315](CVE-2025-55315-digitalsnemesis_CVE-2025-55315.md) 🔴 ✅

**名称:** CVE-2025-55315-ASP.NET安全特性绕过  
**类型:** HTTP请求走私  
**风险:** 高危，可能导致未授权访问、数据泄露、应用compromise、声誉损害  
**投毒风险:** 90%  
**发现时间:** 2025-10-17  
**POC仓库:** [CVE-2025-55315](https://github.com/digitalsnemesis/CVE-2025-55315)  

---

### [CVE-2025-9242](CVE-2025-9242-watchtowrlabs_watchTowr-vs-WatchGuard-CVE-2025-9242.md) 🔴 ✅

**名称:** CVE-2025-9242 WatchGuard Firebox iked Out of Bounds Write Vulnerability  
**类型:** Out-of-bounds Write  
**风险:** Critical，远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-10-17  
**POC仓库:** [watchTowr-vs-WatchGuard-CVE-2025-9242](https://github.com/watchtowrlabs/watchTowr-vs-WatchGuard-CVE-2025-9242)  

---

### [CVE-2025-9242](CVE-2025-9242-pulsecipher_CVE-2025-9242.md) 🔴 ✅

**名称:** CVE-2025-9242-WatchGuard-Fireware-OS-Out-of-bounds-Write  
**类型:** Out-of-bounds Write  
**风险:** 高危，可能导致远程代码执行和系统完全控制  
**投毒风险:** 60%  
**发现时间:** 2025-10-17  
**POC仓库:** [CVE-2025-9242](https://github.com/pulsecipher/CVE-2025-9242)  

---

### [CVE-2025-55315](CVE-2025-55315-bytetornado_CVE-2025-55315.md) 🔴 

**名称:** CVE-2025-55315-ASP.NET Security Feature Bypass Vulnerability  
**类型:** HTTP Request Smuggling  
**风险:** 高危，可能导致安全特性绕过  
**投毒风险:** 0%  
**发现时间:** 2025-10-17  
**POC仓库:** [CVE-2025-55315](https://github.com/bytetornado/CVE-2025-55315)  

---

### [CVE-2025-60500](CVE-2025-60500-H4zaz_CVE-2025-60500.md) 🔴 ✅

**名称:** CVE-2025-60500 - QDocs Smart School 7.1 远程代码执行  
**类型:** 文件上传/逻辑缺陷  
**风险:** 高危，远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-10-17  
**POC仓库:** [CVE-2025-60500](https://github.com/H4zaz/CVE-2025-60500)  

---

### [CVE-2024-13513](CVE-2024-13513-0axz-tools_CVE-2024-13513.py.md) 🔴 ✅

**名称:** CVE-2024-13513 - Oliver POS 敏感信息泄露导致权限提升  
**类型:** 敏感信息泄露导致权限提升  
**风险:** 高危，可能导致敏感信息泄露和站点完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-10-17  
**POC仓库:** [CVE-2024-13513.py](https://github.com/0axz-tools/CVE-2024-13513.py)  

---

### [CVE-2024-51793](CVE-2024-51793-0axz-tools_CVE-2024-51793.md) 🔴 ✅

**名称:** CVE-2024-51793-Computer Repair Shop-任意文件上传  
**类型:** 任意文件上传  
**风险:** 高危，允许攻击者上传Web Shell到Web服务器，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-10-17  
**POC仓库:** [CVE-2024-51793](https://github.com/0axz-tools/CVE-2024-51793)  

---

### [CVE-2025-32463](CVE-2025-32463-dr4xp_sudo-chroot.md) 🔴 ✅

**名称:** CVE-2025-32463-Sudo-本地提权  
**类型:** 本地提权  
**风险:** 高危，可获得Root权限  
**投毒风险:** 5%  
**发现时间:** 2025-10-17  
**POC仓库:** [sudo-chroot](https://github.com/dr4xp/sudo-chroot)  

---

### [CVE-2023-34804](CVE-2023-34804-Shahibakes_Cve-2023-34804.md) 🔴 ✅

**名称:** CVE-2023-38408 Exploit  
**类型:** Unknown - Potentially OpenSSH Agent Forwarding Vulnerability  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 60%  
**发现时间:** 2025-10-17  
**POC仓库:** [Cve-2023-34804](https://github.com/Shahibakes/Cve-2023-34804)  

---

### [CVE-2025-8088](CVE-2025-8088-blowrrr_cve-2025-8088.md) 🔴 ✅

**名称:** CVE-2025-8088 WinRAR 路径遍历漏洞  
**类型:** 路径遍历  
**风险:** 高危，允许攻击者执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-10-17  
**POC仓库:** [cve-2025-8088](https://github.com/blowrrr/cve-2025-8088)  

---

### [CVE-2024-27956](CVE-2024-27956-0axz-tools_CVE-2024-27956.md) 🔴 ✅

**名称:** CVE-2024-27956 - WordPress Automatic Plugin SQL 注入  
**类型:** SQL 注入  
**风险:** 高危，可能导致数据库泄露、数据篡改和任意代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-10-17  
**POC仓库:** [CVE-2024-27956](https://github.com/0axz-tools/CVE-2024-27956)  

---

### [CVE-2025-32463](CVE-2025-32463-dr4x-c0d3r_sudo-chroot.md) 🔴 ✅

**名称:** CVE-2025-32463-Sudo-本地权限提升  
**类型:** 本地权限提升  
**风险:** 高危，允许本地用户获取root权限  
**投毒风险:** 0%  
**发现时间:** 2025-10-17  
**POC仓库:** [sudo-chroot](https://github.com/dr4x-c0d3r/sudo-chroot)  

---

### [CVE-2025-55315](CVE-2025-55315-RootAid_CVE-2025-55315.md) 🔴 

**名称:** CVE-2025-55315 ASP.NET Security Feature Bypass Vulnerability  
**类型:** HTTP Request Smuggling  
**风险:** 高危，可能导致安全功能绕过  
**投毒风险:** 0%  
**发现时间:** 2025-10-17  
**POC仓库:** [CVE-2025-55315](https://github.com/RootAid/CVE-2025-55315)  

---

### [CVE-2025-8081](CVE-2025-8081-LyesH4ck_CVE-2025-8081-Elementor.md) 🔴 ✅

**名称:** CVE-2025-8081 - Elementor Arbitrary File Read Vulnerability  
**类型:** Arbitrary File Read  
**风险:** 高危，可读取服务器敏感文件，导致数据库凭据泄露  
**投毒风险:** 0%  
**发现时间:** 2025-10-17  
**POC仓库:** [CVE-2025-8081-Elementor](https://github.com/LyesH4ck/CVE-2025-8081-Elementor)  

---

### [CVE-2025-11371](CVE-2025-11371-lap1nou_CVE-2025-11371.md) 🔴 ✅

**名称:** CVE-2025-11371-Gladinet CentreStack and TrioFox-LFI  
**类型:** 本地文件包含 (LFI)  
**风险:** 高危，可能导致敏感信息泄露和远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-10-17  
**POC仓库:** [CVE-2025-11371](https://github.com/lap1nou/CVE-2025-11371)  

---

### [CVE-2025-24990](CVE-2025-24990-moiz-2x_CVE-2025-24990_POC.md) 🔴 ✅

**名称:** CVE-2025-24990 - Windows Agere Modem Driver 权限提升漏洞  
**类型:** 权限提升  
**风险:** 高危，允许低权限用户提升至系统权限  
**投毒风险:** 5%  
**发现时间:** 2025-10-17  
**POC仓库:** [CVE-2025-24990_POC](https://github.com/moiz-2x/CVE-2025-24990_POC)  

---

### [CVE-2025-60751](CVE-2025-60751-zer0matt_CVE-2025-60751.md) 🔴 ✅

**名称:** CVE-2025-60751 - Geographiclib Stack Buffer Overflow  
**类型:** 栈缓冲区溢出  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-10-17  
**POC仓库:** [CVE-2025-60751](https://github.com/zer0matt/CVE-2025-60751)  

---

### [CVE-2025-58718](CVE-2025-58718-callinston_CVE-2025-58718.md) 🔴 ✅

**名称:** CVE-2025-58718: Remote Desktop Client RCE  
**类型:** Use-After-Free  
**风险:** 高危，允许未经授权的攻击者通过网络执行任意代码。  
**投毒风险:** 30%  
**发现时间:** 2025-10-17  
**POC仓库:** [CVE-2025-58718](https://github.com/callinston/CVE-2025-58718)  

---

### [CVE-2017-10003](CVE-2017-10003-letsr00t_CVE-2017-1000367.md) 🟡 ✅

**名称:** CVE-2017-10003-Solaris-权限提升/DoS  
**类型:** 权限提升/DoS  
**风险:** 中危，可导致敏感数据读取、修改以及部分拒绝服务  
**投毒风险:** 5%  
**发现时间:** 2025-10-17  
**POC仓库:** [CVE-2017-1000367](https://github.com/letsr00t/CVE-2017-1000367)  

---

### [CVE-2025-10041](CVE-2025-10041-Kai-One001_WordPress-Flex-QR-Code-Generator---CVE-2025-10041.md) 🔴 ✅

**名称:** CVE-2025-10041：Flex QR Code Generator 插件任意文件上传漏洞  
**类型:** 任意文件上传  
**风险:** 高危，允许未授权用户上传恶意文件并可能导致远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-10-17  
**POC仓库:** [WordPress-Flex-QR-Code-Generator---CVE-2025-10041](https://github.com/Kai-One001/WordPress-Flex-QR-Code-Generator---CVE-2025-10041)  

---

### [CVE-2025-52136](CVE-2025-52136-f1r3K0_CVE-2025-52136.md) 🔴 ✅

**名称:** CVE-2025-52136-EMQX-插件安装RCE  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-10-17  
**POC仓库:** [CVE-2025-52136](https://github.com/f1r3K0/CVE-2025-52136)  

---

### [CVE-2025-24893](CVE-2025-24893-Yukik4z3_CVE-2025-24893.md) 🔴 ✅

**名称:** CVE-2025-24893-XWiki-RCE  
**类型:** 远程代码执行  
**风险:** 高危，未经身份验证的远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-10-17  
**POC仓库:** [CVE-2025-24893](https://github.com/Yukik4z3/CVE-2025-24893)  

---

### [CVE-2025-60752](CVE-2025-60752-zer0matt_CVE-2025-60752.md) 🔴 ✅

**名称:** CVE-2025-60752  
**类型:** 缓冲区溢出 (推测)  
**风险:** 高危，可能导致拒绝服务或远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-10-17  
**POC仓库:** [CVE-2025-60752](https://github.com/zer0matt/CVE-2025-60752)  

---

### [CVE-2019-19781](CVE-2019-19781-autocode07_cisagov__check-cve-2019-19781.4142e02b.md) 🔴 ✅

**名称:** CVE-2019-19781 - Citrix ADC/Gateway 目录遍历漏洞  
**类型:** 目录遍历  
**风险:** 高危，可能导致敏感信息泄露和远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-10-17  
**POC仓库:** [cisagov__check-cve-2019-19781.4142e02b](https://github.com/autocode07/cisagov__check-cve-2019-19781.4142e02b)  

---

### [CVE-2019-5591](CVE-2019-5591-ayewo_fortios-ldap-mitm-poc-CVE-2019-5591.md) 🟡 ✅

**名称:** CVE-2019-5591-FortiOS-LDAP MITM  
**类型:** MITM  
**风险:** 中危，可能导致敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-10-16  
**POC仓库:** [fortios-ldap-mitm-poc-CVE-2019-5591](https://github.com/ayewo/fortios-ldap-mitm-poc-CVE-2019-5591)  

---

### [CVE-2025-8088](CVE-2025-8088-aldisakti2_CVE-2025-8088-BUILDER-Winrar-Tool.md) 🔴 ✅

**名称:** CVE-2025-8088 WinRAR Path Traversal  
**类型:** Path Traversal  
**风险:** 高危，允许攻击者执行任意代码  
**投毒风险:** 20%  
**发现时间:** 2025-10-16  
**POC仓库:** [CVE-2025-8088-BUILDER-Winrar-Tool](https://github.com/aldisakti2/CVE-2025-8088-BUILDER-Winrar-Tool)  

---

### [CVE-2025-49553](CVE-2025-49553-silentexploitexe_CVE-2025-49553.md) 🔴 ✅

**名称:** CVE-2025-49553-Adobe Connect-DOM-based XSS  
**类型:** DOM-based XSS  
**风险:** 高危，可导致会话劫持，信息泄露  
**投毒风险:** 80%  
**发现时间:** 2025-10-16  
**POC仓库:** [CVE-2025-49553](https://github.com/silentexploitexe/CVE-2025-49553)  

---

### [CVE-2025-10850](CVE-2025-10850-pulsecipher_CVE-2025-10850.md) 🔴 ✅

**名称:** CVE-2025-10850 - Felan Framework Hardcoded Credentials  
**类型:** 不当身份验证/硬编码凭据  
**风险:** 高危，可能导致任意用户登录，数据泄露，权限提升  
**投毒风险:** 95%  
**发现时间:** 2025-10-16  
**POC仓库:** [CVE-2025-10850](https://github.com/pulsecipher/CVE-2025-10850)  

---

### [CVE-2025-55315](CVE-2025-55315-sirredbeard_CVE-2025-55315-repro.md) 🔴 ✅

**名称:** CVE-2025-55315-ASP.NET Security Feature Bypass Vulnerability  
**类型:** HTTP Request Smuggling  
**风险:** 高危，可能导致安全特性绕过  
**投毒风险:** 10%  
**发现时间:** 2025-10-16  
**POC仓库:** [CVE-2025-55315-repro](https://github.com/sirredbeard/CVE-2025-55315-repro)  

---

### [CVE-2025-55315](CVE-2025-55315-snowcrashlord_CVE-2025-55315.md) 🔴 ✅

**名称:** CVE-2025-55315-ASP.NET Security Feature Bypass  
**类型:** HTTP Request Smuggling  
**风险:** 高危，可能导致安全功能绕过，信息泄露，权限提升等  
**投毒风险:** 10%  
**发现时间:** 2025-10-16  
**POC仓库:** [CVE-2025-55315](https://github.com/snowcrashlord/CVE-2025-55315)  

---

### [CVE-2025-62376](CVE-2025-62376-digitalsnemesis_CVE-2025-62376.md) 🔴 ✅

**名称:** CVE-2025-62376 - pwn.college DOJO Improper Authentication  
**类型:** 身份验证绕过  
**风险:** 高危，可完全控制受害者Windows VM  
**投毒风险:** 10%  
**发现时间:** 2025-10-16  
**POC仓库:** [CVE-2025-62376](https://github.com/digitalsnemesis/CVE-2025-62376)  

---

### [CVE-2025-55315](CVE-2025-55315-nickcopi_CVE-2025-55315-detection-playground.md) 🔴 ✅

**名称:** CVE-2025-55315-ASP.NET Core-HTTP请求走私  
**类型:** HTTP Request Smuggling  
**风险:** 高危，允许授权攻击者绕过网络上的安全功能  
**投毒风险:** 0%  
**发现时间:** 2025-10-16  
**POC仓库:** [CVE-2025-55315-detection-playground](https://github.com/nickcopi/CVE-2025-55315-detection-playground)  

---

### [CVE-2025-56450](CVE-2025-56450-apboss123_CVE-2025-56450.md) 🔴 ✅

**名称:** CVE-2025-56450-Log2Space Subscriber Management Software-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露、数据篡改和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-10-16  
**POC仓库:** [CVE-2025-56450](https://github.com/apboss123/CVE-2025-56450)  

---

### [CVE-2025-61882](CVE-2025-61882-AdityaBhatt3010_CVE-2025-61882-Oracle-E-Business-Suite-Pre-Auth-RCE-Exploit.md) 🔴 ✅

**名称:** CVE-2025-61882 - Oracle E-Business Suite Pre-Auth RCE  
**类型:** 远程代码执行  
**风险:** 高危，可以完全控制 Oracle Concurrent Processing  
**投毒风险:** 10%  
**发现时间:** 2025-10-16  
**POC仓库:** [CVE-2025-61882-Oracle-E-Business-Suite-Pre-Auth-RCE-Exploit](https://github.com/AdityaBhatt3010/CVE-2025-61882-Oracle-E-Business-Suite-Pre-Auth-RCE-Exploit)  

---

### [CVE-2024-31497](CVE-2024-31497-sh1k4ku_CVE-2024-31497.md) 🔴 ✅

**名称:** CVE-2024-31497-PuTTY-ECDSA私钥泄露  
**类型:** ECDSA私钥泄露  
**风险:** 高危，可能导致身份伪造和供应链攻击  
**投毒风险:** 10%  
**发现时间:** 2025-10-16  
**POC仓库:** [CVE-2024-31497](https://github.com/sh1k4ku/CVE-2024-31497)  

---

### [CVE-2024-31497](CVE-2024-31497-edutko_cve-2024-31497.md) 🔴 ✅

**名称:** CVE-2024-31497-PuTTY-ECDSA私钥泄露  
**类型:** 私钥泄露  
**风险:** 高危，可能导致身份伪造和供应链攻击  
**投毒风险:** 10%  
**发现时间:** 2025-10-16  
**POC仓库:** [cve-2024-31497](https://github.com/edutko/cve-2024-31497)  

---

### [CVE-2024-31497](CVE-2024-31497-HugoBond_CVE-2024-31497-POC.md) 🔴 ✅

**名称:** CVE-2024-31497-PuTTY-ECDSA私钥泄露  
**类型:** 私钥泄露  
**风险:** 高危，可能导致身份伪造和供应链攻击  
**投毒风险:** 10%  
**发现时间:** 2025-10-16  
**POC仓库:** [CVE-2024-31497-POC](https://github.com/HugoBond/CVE-2024-31497-POC)  

---

### [CVE-2024-31497](CVE-2024-31497-LukaWynants_Onderzoek_CVE-2024-31497-POC.md) 🔴 ✅

**名称:** CVE-2024-31497-PuTTY-ECDSA密钥恢复  
**类型:** ECDSA密钥恢复  
**风险:** 高危，可能导致密钥泄露和供应链攻击  
**投毒风险:** 10%  
**发现时间:** 2025-10-16  
**POC仓库:** [Onderzoek_CVE-2024-31497-POC](https://github.com/LukaWynants/Onderzoek_CVE-2024-31497-POC)  

---

### [CVE-2025-62410](CVE-2025-62410-SubZeroHackerz_CVE-2025-62410.md) 🔴 ✅

**名称:** CVE-2025-62410-happy-dom-原型污染  
**类型:** 原型污染  
**风险:** 高危，可能导致代码执行，权限提升  
**投毒风险:** 90%  
**发现时间:** 2025-10-16  
**POC仓库:** [CVE-2025-62410](https://github.com/SubZeroHackerz/CVE-2025-62410)  

---

### [CVE-2025-49553](CVE-2025-49553-SysRooter_CVE-2025-49553.md) 🔴 ✅

**名称:** CVE-2025-49553-Adobe Connect-DOM型XSS  
**类型:** DOM型XSS  
**风险:** 高危，可导致会话劫持，提升权限  
**投毒风险:** 10%  
**发现时间:** 2025-10-16  
**POC仓库:** [CVE-2025-49553](https://github.com/SysRooter/CVE-2025-49553)  

---

### [CVE-2022-1364](CVE-2022-1364-A1Lin_cve-2022-1364.md) 🔴 ✅

**名称:** CVE-2022-1364 - Chrome V8 Turbofan 类型混淆漏洞  
**类型:** 类型混淆  
**风险:** 高危，可能导致堆损坏和任意代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-10-16  
**POC仓库:** [cve-2022-1364](https://github.com/A1Lin/cve-2022-1364)  

---

### [CVE-2022-1364](CVE-2022-1364-interruptlabs_uc_browser_poc_CVE-2022-1364.md) 🔴 ✅

**名称:** CVE-2022-1364 - Google Chrome V8 Turbofan Type Confusion  
**类型:** 类型混淆导致堆损坏  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 80%  
**发现时间:** 2025-10-16  
**POC仓库:** [uc_browser_poc_CVE-2022-1364](https://github.com/interruptlabs/uc_browser_poc_CVE-2022-1364)  

---

### [CVE-2025-62376](CVE-2025-62376-ProtocolAudit_CVE-2025-62376.md) 🔴 ✅

**名称:** CVE-2025-62376-pwn.college DOJO-权限绕过  
**类型:** 权限绕过/不当身份验证  
**风险:** 高危，可能导致未经授权的Windows VM访问，数据泄露和篡改  
**投毒风险:** 95%  
**发现时间:** 2025-10-16  
**POC仓库:** [CVE-2025-62376](https://github.com/ProtocolAudit/CVE-2025-62376)  

---

### [CVE-2025-55315](CVE-2025-55315-HelixProxy_CVE-2025-55315.md) 🔴 ✅

**名称:** CVE-2025-55315-ASP.NET Core-HTTP请求走私  
**类型:** HTTP请求走私  
**风险:** 高危，可能导致安全特性绕过、信息泄露、权限提升甚至远程代码执行  
**投毒风险:** 95%  
**发现时间:** 2025-10-16  
**POC仓库:** [CVE-2025-55315](https://github.com/HelixProxy/CVE-2025-55315)  

---

### [CVE-2018-18441](CVE-2018-18441-AIDENTHOMASboi_CVE-2018-18441-exploit.md) 🟡 ✅

**名称:** CVE-2018-18441-D-Link摄像头信息泄露  
**类型:** 信息泄露  
**风险:** 中危，可能导致敏感信息泄露  
**投毒风险:** 95%  
**发现时间:** 2025-10-16  
**POC仓库:** [CVE-2018-18441-exploit](https://github.com/AIDENTHOMASboi/CVE-2018-18441-exploit)  

---

### [CVE-2025-61882](CVE-2025-61882-MindflareX_CVE-2025-61882-POC.md) 🔴 ✅

**名称:** CVE-2025-61882-Oracle Concurrent Processing-RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 5%  
**发现时间:** 2025-10-16  
**POC仓库:** [CVE-2025-61882-POC](https://github.com/MindflareX/CVE-2025-61882-POC)  

---

### [CVE-2020-35667](CVE-2020-35667-Diekgbbtt_CVE-2020-35667-PoC.md) 🟡 ✅

**名称:** CVE-2020-35667-JetBrains TeamCity SSRF  
**类型:** SSRF (服务器端请求伪造)  
**风险:** 中危，可能暴露用户凭据  
**投毒风险:** 10%  
**发现时间:** 2025-10-15  
**POC仓库:** [CVE-2020-35667-PoC](https://github.com/Diekgbbtt/CVE-2020-35667-PoC)  

---

### [CVE-2025-61301](CVE-2025-61301-eGkritsis_CVE-2025-61301.md) 🔴 ✅

**名称:** CVE-2025-61301 - CAPEv2: 拒绝分析服务漏洞  
**类型:** 拒绝服务 (Denial-of-Service)  
**风险:** 高危，导致无法进行恶意软件分析  
**投毒风险:** 5%  
**发现时间:** 2025-10-15  
**POC仓库:** [CVE-2025-61301](https://github.com/eGkritsis/CVE-2025-61301)  

---

### [CVE-2025-61303](CVE-2025-61303-eGkritsis_CVE-2025-61303.md) 🔴 ✅

**名称:** CVE-2025-61303 - RecordedFuture Triage: Denial-Of-Analysis via Recursive Process Forking  
**类型:** 拒绝服务 (Denial-of-Analysis)  
**风险:** 高危，可能导致分析引擎失效，错过恶意行为检测  
**投毒风险:** 0%  
**发现时间:** 2025-10-15  
**POC仓库:** [CVE-2025-61303](https://github.com/eGkritsis/CVE-2025-61303)  

---

### [CVE-2025-11832](CVE-2025-11832-SilentPacket-cmd_CVE-2025-11832.md) 🔴 ✅

**名称:** CVE-2025-11832-AzureAccessTechnology-资源耗尽  
**类型:** 资源耗尽/拒绝服务(DoS)  
**风险:** 高危，可能导致服务中断或系统崩溃  
**投毒风险:** 95%  
**发现时间:** 2025-10-15  
**POC仓库:** [CVE-2025-11832](https://github.com/SilentPacket-cmd/CVE-2025-11832)  

---

### [CVE-2025-61882](CVE-2025-61882-RootAid_CVE-2025-61882.md) 🔴 ✅

**名称:** CVE-2025-61882-Oracle Concurrent Processing-未授权接管  
**类型:** 未授权接管  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-10-15  
**POC仓库:** [CVE-2025-61882](https://github.com/RootAid/CVE-2025-61882)  

---

### [CVE-2024-28231](CVE-2024-28231-grimmmbo_ros2_CVE-2024-28231.md) 🔴 ✅

**名称:** CVE-2024-28231 - Fast-DDS 堆缓冲区溢出  
**类型:** 堆缓冲区溢出  
**风险:** 高危，可能导致远程拒绝服务或远程代码执行（取决于具体实现）。  
**投毒风险:** 10%  
**发现时间:** 2025-10-15  
**POC仓库:** [ros2_CVE-2024-28231](https://github.com/grimmmbo/ros2_CVE-2024-28231)  

---

### [CVE-2025-8088](CVE-2025-8088-Snorx-cyber_CVE-2025-8088-builder.md) 🔴 ✅

**名称:** CVE-2025-8088 WinRAR Path Traversal  
**类型:** Path Traversal  
**风险:** 高危，可能导致任意代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-10-15  
**POC仓库:** [CVE-2025-8088-builder](https://github.com/Snorx-cyber/CVE-2025-8088-builder)  

---

### [CVE-2025-10294](CVE-2025-10294-FixingPhantom_CVE-2025-10294.md) 🔴 ✅

**名称:** CVE-2025-10294-OwnID Passwordless Login-身份验证绕过  
**类型:** 身份验证绕过  
**风险:** 高危，可能导致数据泄露、站点篡改、恶意软件注入或完全的站点入侵  
**投毒风险:** 20%  
**发现时间:** 2025-10-15  
**POC仓库:** [CVE-2025-10294](https://github.com/FixingPhantom/CVE-2025-10294)  

---

### [CVE-2017-10271](CVE-2017-10271-lonehand_Oracle-WebLogic-CVE-2017-10271-master.md) 🔴 ✅

**名称:** CVE-2017-10271 WebLogic WLS-WSAT 远程命令执行漏洞  
**类型:** 远程命令执行  
**风险:** 高危，可导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-10-15  
**POC仓库:** [Oracle-WebLogic-CVE-2017-10271-master](https://github.com/lonehand/Oracle-WebLogic-CVE-2017-10271-master)  

---

### [CVE-2024-53677](CVE-2024-53677-seoyoung-kang_CVE-2024-53677.md) 🔴 ✅

**名称:** CVE-2024-53677-Apache Struts 文件上传路径遍历导致RCE  
**类型:** 文件上传/路径遍历/RCE  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 2%  
**发现时间:** 2025-10-15  
**POC仓库:** [CVE-2024-53677](https://github.com/seoyoung-kang/CVE-2024-53677)  

---

### [CVE-2025-9967](CVE-2025-9967-OraclePatch_CVE-2025-9967.md) 🔴 ✅

**名称:** CVE-2025-9967-Orion SMS OTP Verification-账户接管  
**类型:** 账户接管  
**风险:** 高危，可导致账户被非法控制，数据泄露，权限提升  
**投毒风险:** 90%  
**发现时间:** 2025-10-15  
**POC仓库:** [CVE-2025-9967](https://github.com/OraclePatch/CVE-2025-9967)  

---

### [CVE-2025-10041](CVE-2025-10041-AlloyRecon_CVE-2025-10041.md) 🔴 ✅

**名称:** CVE-2025-10041-Flex QR Code Generator-任意文件上传  
**类型:** 任意文件上传  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-10-15  
**POC仓库:** [CVE-2025-10041](https://github.com/AlloyRecon/CVE-2025-10041)  

---

### [CVE-2025-10294](CVE-2025-10294-HexSentinel-cmd_CVE-2025-10294.md) 🔴 ✅

**名称:** CVE-2025-10294 - OwnID Passwordless Login - Authentication Bypass  
**类型:** Authentication Bypass  
**风险:** Critical, allows unauthenticated attackers to log in as any user, including administrators.  
**投毒风险:** 80%  
**发现时间:** 2025-10-15  
**POC仓库:** [CVE-2025-10294](https://github.com/HexSentinel-cmd/CVE-2025-10294)  

---

### [CVE-2025-10294](CVE-2025-10294-h4xnz_CVE-2025-10294-POC.md)  ✅

**名称:** CVE-2025-10294-OwnID Passwordless Login-Authentication Bypass  
**类型:** 身份验证绕过  
**风险:** 严重，可能导致未经授权的访问和完全控制  
**投毒风险:** 80%  
**发现时间:** 2025-10-15  
**POC仓库:** [CVE-2025-10294-POC](https://github.com/h4xnz/CVE-2025-10294-POC)  

---

### [CVE-2025-61882](CVE-2025-61882-HexSentinel-cmd_CVE-2025-61882.md) 🔴 ✅

**名称:** CVE-2025-61882-Oracle Concurrent Processing-任意文件读取/控制  
**类型:** 任意文件读取/控制  
**风险:** 高危，可完全控制 Oracle Concurrent Processing 系统  
**投毒风险:** 60%  
**发现时间:** 2025-10-15  
**POC仓库:** [CVE-2025-61882](https://github.com/HexSentinel-cmd/CVE-2025-61882)  

---

### [CVE-2017-10271](CVE-2017-10271-s3xy_CVE-2017-10271.md) 🔴 ✅

**名称:** CVE-2017-10271-WebLogic Server-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-10-15  
**POC仓库:** [CVE-2017-10271](https://github.com/s3xy/CVE-2017-10271)  

---

### [CVE-2017-10271](CVE-2017-10271-ZH3FENG_PoCs-Weblogic_2017_10271.md) 🔴 ✅

**名称:** CVE-2017-10271-WebLogic-反序列化漏洞  
**类型:** 反序列化漏洞  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-10-15  
**POC仓库:** [PoCs-Weblogic_2017_10271](https://github.com/ZH3FENG/PoCs-Weblogic_2017_10271)  

---

### [CVE-2017-10271](CVE-2017-10271-cjjduck_weblogic_wls_wsat_rce.md) 🔴 ✅

**名称:** CVE-2017-10271-WebLogic-WLS-WSAT远程命令执行  
**类型:** 远程命令执行  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 20%  
**发现时间:** 2025-10-15  
**POC仓库:** [weblogic_wls_wsat_rce](https://github.com/cjjduck/weblogic_wls_wsat_rce)  

---

### [CVE-2017-10271](CVE-2017-10271-Luffin_CVE-2017-10271.md) 🔴 ✅

**名称:** CVE-2017-10271 Oracle WebLogic Server WLS Security 组件反序列化漏洞  
**类型:** 反序列化漏洞  
**风险:** 高危，可能导致远程代码执行，服务器完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-10-15  
**POC仓库:** [CVE-2017-10271](https://github.com/Luffin/CVE-2017-10271)  

---

### [CVE-2017-10271](CVE-2017-10271-peterpeter228_Oracle-WebLogic-CVE-2017-10271.md) 🔴 ✅

**名称:** CVE-2017-10271 / CVE-2017-3506 Oracle WebLogic wls-wsat RCE  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-10-15  
**POC仓库:** [Oracle-WebLogic-CVE-2017-10271](https://github.com/peterpeter228/Oracle-WebLogic-CVE-2017-10271)  

---

### [CVE-2017-10271](CVE-2017-10271-SuperHacker-liuan_cve-2017-10271-poc.md) 🔴 ✅

**名称:** CVE-2017-10271  
**类型:** WebLogic Server反序列化漏洞  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-10-15  
**POC仓库:** [cve-2017-10271-poc](https://github.com/SuperHacker-liuan/cve-2017-10271-poc)  

---

### [CVE-2017-10271](CVE-2017-10271-JackyTsuuuy_weblogic_wls_rce_poc-exp.md) 🔴 ✅

**名称:** CVE-2017-10271-WebLogic-WLS-WSAT组件反序列化RCE  
**类型:** 反序列化远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-10-15  
**POC仓库:** [weblogic_wls_rce_poc-exp](https://github.com/JackyTsuuuy/weblogic_wls_rce_poc-exp)  

---

### [CVE-2017-10271](CVE-2017-10271-c0mmand3rOpSec_CVE-2017-10271.md) 🔴 ✅

**名称:** CVE-2017-10271-Oracle WebLogic Server-反序列化RCE  
**类型:** 反序列化RCE  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-10-15  
**POC仓库:** [CVE-2017-10271](https://github.com/c0mmand3rOpSec/CVE-2017-10271)  

---

### [CVE-2017-10271](CVE-2017-10271-r4b3rt_CVE-2017-10271.md) 🔴 ✅

**名称:** CVE-2017-10271-WebLogic-WLS-WSAT反序列化RCE  
**类型:** 反序列化远程代码执行  
**风险:** 高危，可导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-10-15  
**POC仓库:** [CVE-2017-10271](https://github.com/r4b3rt/CVE-2017-10271)  

---

### [CVE-2017-10271](CVE-2017-10271-ETOCheney_JavaDeserialization.md) 🔴 ✅

**名称:** CVE-2017-10271-Oracle WebLogic Server-反序列化漏洞  
**类型:** 反序列化  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-10-15  
**POC仓库:** [JavaDeserialization](https://github.com/ETOCheney/JavaDeserialization)  

---

### [CVE-2017-10271](CVE-2017-10271-kbsec_Weblogic_Wsat_RCE.md) 🔴 ✅

**名称:** CVE-2017-10271 - Oracle WebLogic Server WLS Security 组件远程代码执行漏洞  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可完全控制受影响的WebLogic服务器  
**投毒风险:** 10%  
**发现时间:** 2025-10-15  
**POC仓库:** [Weblogic_Wsat_RCE](https://github.com/kbsec/Weblogic_Wsat_RCE)  

---

### [CVE-2017-10271](CVE-2017-10271-Yuusuke4_WebLogic_CNVD_C_2019_48814.md) 🔴 ✅

**名称:** CVE-2017-10271-Oracle WebLogic Server-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器接管  
**投毒风险:** 10%  
**发现时间:** 2025-10-15  
**POC仓库:** [WebLogic_CNVD_C_2019_48814](https://github.com/Yuusuke4/WebLogic_CNVD_C_2019_48814)  

---

### [CVE-2017-10271](CVE-2017-10271-7kbstorm_WebLogic_CNVD_C2019_48814.md) 🔴 ✅

**名称:** CVE-2017-10271-WebLogic-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-10-15  
**POC仓库:** [WebLogic_CNVD_C2019_48814](https://github.com/7kbstorm/WebLogic_CNVD_C2019_48814)  

---

### [CVE-2017-10271](CVE-2017-10271-ianxtianxt_-CVE-2017-10271-.md) 🔴 ✅

**名称:** CVE-2017-10271-WebLogic-Java反序列化  
**类型:** Java反序列化漏洞  
**风险:** 高危，可能导致远程代码执行，服务器完全控制  
**投毒风险:** 30%  
**发现时间:** 2025-10-15  
**POC仓库:** [-CVE-2017-10271-](https://github.com/ianxtianxt/-CVE-2017-10271-)  

---

### [CVE-2017-10271](CVE-2017-10271-pssss_CVE-2017-10271.md) 🔴 ✅

**名称:** CVE-2017-10271-WebLogic-反序列化漏洞  
**类型:** 反序列化漏洞  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-10-15  
**POC仓库:** [CVE-2017-10271](https://github.com/pssss/CVE-2017-10271)  

---

### [CVE-2017-10271](CVE-2017-10271-Cymmetria_weblogic_honeypot.md) 🔴 ✅

**名称:** CVE-2017-10271-WebLogic-RCE  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-10-15  
**POC仓库:** [weblogic_honeypot](https://github.com/Cymmetria/weblogic_honeypot)  

---

### [CVE-2017-10271](CVE-2017-10271-testwc_CVE-2017-10271.md) 🔴 ✅

**名称:** CVE-2017-10271 - Oracle WebLogic Server WLS Security 远程命令执行  
**类型:** 远程命令执行  
**风险:** 高危，可完全控制 WebLogic Server  
**投毒风险:** 5%  
**发现时间:** 2025-10-15  
**POC仓库:** [CVE-2017-10271](https://github.com/testwc/CVE-2017-10271)  

---

### [CVE-2017-10271](CVE-2017-10271-shack2_javaserializetools.md) 🔴 ✅

**名称:** CVE-2017-10271-Oracle WebLogic Server-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-10-15  
**POC仓库:** [javaserializetools](https://github.com/shack2/javaserializetools)  

---

### [CVE-2017-10271](CVE-2017-10271-Al1ex_CVE-2017-10271.md) 🔴 ✅

**名称:** CVE-2017-10271-Oracle WebLogic Server-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-10-15  
**POC仓库:** [CVE-2017-10271](https://github.com/Al1ex/CVE-2017-10271)  

---

### [CVE-2017-10271](CVE-2017-10271-cved-sources_cve-2017-10271.md) 🔴 ✅

**名称:** CVE-2017-10271 - Oracle WebLogic Server WLS Security 组件远程代码执行漏洞  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-10-15  
**POC仓库:** [cve-2017-10271](https://github.com/cved-sources/cve-2017-10271)  

---

### [CVE-2017-10271](CVE-2017-10271-kkirsche_CVE-2017-10271.md) 🔴 ✅

**名称:** CVE-2017-10271 WebLogic wls-wsat 组件反序列化 RCE  
**类型:** 反序列化远程代码执行  
**风险:** 高危，可导致服务器完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-10-15  
**POC仓库:** [CVE-2017-10271](https://github.com/kkirsche/CVE-2017-10271)  

---

### [CVE-2017-10271](CVE-2017-10271-XHSecurity_Oracle-WebLogic-CVE-2017-10271.md) 🔴 ✅

**名称:** CVE-2017-10271 WebLogic WLS 组件远程代码执行漏洞  
**类型:** 远程代码执行  
**风险:** 高危，可完全控制 WebLogic Server  
**投毒风险:** 10%  
**发现时间:** 2025-10-15  
**POC仓库:** [Oracle-WebLogic-CVE-2017-10271](https://github.com/XHSecurity/Oracle-WebLogic-CVE-2017-10271)  

---

### [CVE-2017-10271](CVE-2017-10271-seoyoung-kang_CVE-2017-10271.md) 🔴 ✅

**名称:** CVE-2017-10271  
**类型:** 反序列化漏洞  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 2%  
**发现时间:** 2025-10-15  
**POC仓库:** [CVE-2017-10271](https://github.com/seoyoung-kang/CVE-2017-10271)  

---

### [CVE-2025-11371](CVE-2025-11371-NetVanguard-cmd_CVE-2025-11371.md) 🔴 ✅

**名称:** CVE-2025-11371 - Gladinet CentreStack and TrioFox Local File Inclusion Flaw  
**类型:** Local File Inclusion (LFI)  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-10-15  
**POC仓库:** [CVE-2025-11371](https://github.com/NetVanguard-cmd/CVE-2025-11371)  

---

### [CVE-2021-24762](CVE-2021-24762-c4cnm_Exploit_CVE-2021-24762.md) 🔴 ✅

**名称:** CVE-2021-24762-Perfect Survey-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露和服务器控制  
**投毒风险:** 0%  
**发现时间:** 2025-10-15  
**POC仓库:** [Exploit_CVE-2021-24762](https://github.com/c4cnm/Exploit_CVE-2021-24762)  

---

### [CVE-2025-5947](CVE-2025-5947-NightlyAudit_CVE-2025-5947.md)  ✅

**名称:** CVE-2025-5947-Service Finder Bookings-身份验证绕过  
**类型:** 身份验证绕过  
**风险:** 严重，可能导致完全控制 WordPress 站点  
**投毒风险:** 95%  
**发现时间:** 2025-10-15  
**POC仓库:** [CVE-2025-5947](https://github.com/NightlyAudit/CVE-2025-5947)  

---

### [CVE-2025-11001](CVE-2025-11001-shalevo13_Se7enSlip.md) 🔴 ✅

**名称:** CVE-2023-52169-7-Zip-符号链接穿越漏洞  
**类型:** 符号链接穿越  
**风险:** 高危，可能导致任意文件写入和潜在的代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-10-15  
**POC仓库:** [Se7enSlip](https://github.com/shalevo13/Se7enSlip)  

---

### [CVE-2025-11001](CVE-2025-11001-pacbypass_CVE-2025-11001.md) 🔴 ✅

**名称:** CVE-2025-11001 (推测)  
**类型:** 符号链接漏洞  
**风险:** 高危，可能导致任意文件写入和代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-10-15  
**POC仓库:** [CVE-2025-11001](https://github.com/pacbypass/CVE-2025-11001)  

---

### [CVE-2025-56503](CVE-2025-56503-secxplorers_CVE-2025-56503.md) 🔴 ✅

**名称:** CVE-2025-56503-Sublime Text 4-权限提升  
**类型:** 权限提升  
**风险:** 高危，可导致完全控制受害者系统  
**投毒风险:** 未知，需要分析PoC代码  
**发现时间:** 2025-10-15  
**POC仓库:** [CVE-2025-56503](https://github.com/secxplorers/CVE-2025-56503)  

---

### [CVE-2024-3094](CVE-2024-3094-zpxlz_CVE-2024-3094.md)  ✅

**名称:** CVE-2024-3094 xz supply chain backdoor  
**类型:** 供应链攻击/后门  
**风险:** 严重，可能导致远程代码执行和系统控制  
**投毒风险:** 10%  
**发现时间:** 2025-10-15  
**POC仓库:** [CVE-2024-3094](https://github.com/zpxlz/CVE-2024-3094)  

---

### [CVE-2025-10041](CVE-2025-10041-Nxploited_CVE-2025-10041.md) 🔴 ✅

**名称:** CVE-2025-10041 - Flex QR Code Generator WordPress Plugin Arbitrary File Upload  
**类型:** 任意文件上传  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-10-15  
**POC仓库:** [CVE-2025-10041](https://github.com/Nxploited/CVE-2025-10041)  

---

### [CVE-2025-61882](CVE-2025-61882-AlloySec_CVE-2025-61882.md) 🔴 ✅

**名称:** CVE-2025-61882-Oracle Concurrent Processing-未授权访问  
**类型:** 未授权访问  
**风险:** 高危，可能导致完全控制 Oracle Concurrent Processing  
**投毒风险:** 95%  
**发现时间:** 2025-10-14  
**POC仓库:** [CVE-2025-61882](https://github.com/AlloySec/CVE-2025-61882)  

---

### [CVE-2025-4123](CVE-2025-4123-MorphyKutay_CVE-2025-4123-Exploit.md) 🔴 ✅

**名称:** CVE-2025-4123-Grafana-XSS和Open Redirect  
**类型:** 跨站脚本 (XSS) 和开放重定向  
**风险:** 高危，可能导致用户凭据泄露，SSRF攻击以及任意JavaScript代码执行。  
**投毒风险:** 0%  
**发现时间:** 2025-10-14  
**POC仓库:** [CVE-2025-4123-Exploit](https://github.com/MorphyKutay/CVE-2025-4123-Exploit)  

---

### [CVE-2025-61882](CVE-2025-61882-PrismaScan_CVE-2025-61882.md) 🔴 

**名称:** CVE-2025-61882-Oracle Concurrent Processing-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 1%  
**发现时间:** 2025-10-14  
**POC仓库:** [CVE-2025-61882](https://github.com/PrismaScan/CVE-2025-61882)  

---

### [CVE-2025-9196](CVE-2025-9196-MooseLoveti_Trinity-Audio-CVE-Report.md) 🟡 ✅

**名称:** CVE-2025-9196 - Trinity Audio <= 5.21.0 - 未授权信息泄露  
**类型:** 信息泄露  
**风险:** 中危，可能泄露敏感配置信息，增加攻击面  
**投毒风险:** 0%  
**发现时间:** 2025-10-14  
**POC仓库:** [Trinity-Audio-CVE-Report](https://github.com/MooseLoveti/Trinity-Audio-CVE-Report)  

---

### [CVE-2025-9196](CVE-2025-9196-godfatherofexps_CVE-2025-9196-PoC.md) 🟡 

**名称:** CVE-2025-9196-Trinity Audio - Unauthenticated Information Exposure  
**类型:** 信息泄露  
**风险:** 中危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-10-14  
**POC仓库:** [CVE-2025-9196-PoC](https://github.com/godfatherofexps/CVE-2025-9196-PoC)  

---

### [CVE-2025-7441](CVE-2025-7441-Pwdnx1337_CVE-2025-7441.md) 🔴 ✅

**名称:** CVE-2025-7441-StoryChief-Unauthenticated Arbitrary File Upload  
**类型:** 任意文件上传  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-10-14  
**POC仓库:** [CVE-2025-7441](https://github.com/Pwdnx1337/CVE-2025-7441)  

---

### [CVE-2025-61456](CVE-2025-61456-tansique-17_CVE-2025-61456.md) 🟡 ✅

**名称:** CVE-2025-61456 - E-commerce Project v1.0 反射型XSS  
**类型:** 反射型跨站脚本 (Reflected XSS)  
**风险:** 中危，可能导致用户信息泄露、会话劫持、恶意重定向等  
**投毒风险:** 1%  
**发现时间:** 2025-10-14  
**POC仓库:** [CVE-2025-61456](https://github.com/tansique-17/CVE-2025-61456)  

---

### [CVE-2025-61454](CVE-2025-61454-tansique-17_CVE-2025-61454.md) 🟡 ✅

**名称:** CVE-2025-61454 - E-commerce Project - Reflected XSS  
**类型:** Reflected XSS  
**风险:** 中危，可能导致用户凭证泄露、会话劫持和页面内容篡改  
**投毒风险:** 10%  
**发现时间:** 2025-10-14  
**POC仓库:** [CVE-2025-61454](https://github.com/tansique-17/CVE-2025-61454)  

---

### [CVE-2025-61456](CVE-2025-61456-tansique-17_CVE-2025-61456.md) 🔴 ✅

**名称:** CVE-2025-61455-E-commerce-SQL注入  
**类型:** SQL注入  
**风险:** CRITICAL (CVSS 9.8)，可能导致身份验证绕过、数据泄露、数据篡改/删除、数据库完全控制甚至远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-10-14  
**POC仓库:** [CVE-2025-61456](https://github.com/tansique-17/CVE-2025-61456)  

---

### [CVE-2022-41678](CVE-2022-41678-mbadanoiu_CVE-2022-41678.md) 🔴 ✅

**名称:** CVE-2022-41678: Apache ActiveMQ Jolokia API 远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可以导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-10-14  
**POC仓库:** [CVE-2022-41678](https://github.com/mbadanoiu/CVE-2022-41678)  

---

### [CVE-2022-41678](CVE-2022-41678-URJACK2025_CVE-2022-41678.md) 🔴 ✅

**名称:** CVE-2022-41678-Apache ActiveMQ-RCE  
**类型:** 远程代码执行  
**风险:** 高危，可完全控制服务器  
**投毒风险:** 0%  
**发现时间:** 2025-10-14  
**POC仓库:** [CVE-2022-41678](https://github.com/URJACK2025/CVE-2022-41678)  

---

### [CVE-2025-48384](CVE-2025-48384-mukesh-610_cve-2025-48384-exploit.md) 🔴 ✅

**名称:** CVE-2025-48384-Git-任意代码执行  
**类型:** 任意代码执行  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-10-14  
**POC仓库:** [cve-2025-48384-exploit](https://github.com/mukesh-610/cve-2025-48384-exploit)  

---

### [CVE-2025-56224](CVE-2025-56224-saykino_CVE-2025-56224.md) 🔴 ✅

**名称:** CVE-2025-56224 (OTP) verification Bypass  
**类型:** OTP绕过  
**风险:** 高危，可能导致未经授权的访问和身份冒用  
**投毒风险:** 10%  
**发现时间:** 2025-10-14  
**POC仓库:** [CVE-2025-56224](https://github.com/saykino/CVE-2025-56224)  

---

### [CVE-2024-36971](CVE-2024-36971-Kronk-imp_CVE-2024-36971.md) 🔴 ✅

**名称:** CVE-2024-36971-Linux Kernel __dst_negative_advice() UAF  
**类型:** Use-After-Free (UAF)  
**风险:** 高危，可能导致提权或拒绝服务  
**投毒风险:** 0%  
**发现时间:** 2025-10-14  
**POC仓库:** [CVE-2024-36971](https://github.com/Kronk-imp/CVE-2024-36971)  

---

### [CVE-2025-49844](CVE-2025-49844-angelusrivera_CVE-2025-49844.md) 🔴 ✅

**名称:** CVE-2025-49844-Redis Lua Use-After-Free RCE  
**类型:** Use-After-Free  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-10-14  
**POC仓库:** [CVE-2025-49844](https://github.com/angelusrivera/CVE-2025-49844)  

---

### [CVE-2025-56221](CVE-2025-56221-saykino_CVE-2025-56221.md) 🔴 ✅

**名称:** CVE-2025-56221-SigningHub-身份验证绕过  
**类型:** 身份验证绕过  
**风险:** 高危，可能导致账户泄露和未授权访问  
**投毒风险:** 10%  
**发现时间:** 2025-10-14  
**POC仓库:** [CVE-2025-56221](https://github.com/saykino/CVE-2025-56221)  

---

### [CVE-2025-56219](CVE-2025-56219-saykino_CVE-2025-56219.md) 🔴 ✅

**名称:** CVE-2025-56219 Lack of Rate Limiting – Add User API  
**类型:** DoS  
**风险:** 高危，可能导致服务不可用  
**投毒风险:** 0%  
**发现时间:** 2025-10-14  
**POC仓库:** [CVE-2025-56219](https://github.com/saykino/CVE-2025-56219)  

---

### [CVE-2025-56223](CVE-2025-56223-saykino_CVE-2025-56223.md)  ✅

**名称:** CVE-2025-56223-SigningHub-DoS  
**类型:** 拒绝服务 (DoS)  
**风险:** 高  
**投毒风险:** 1%  
**发现时间:** 2025-10-14  
**POC仓库:** [CVE-2025-56223](https://github.com/saykino/CVE-2025-56223)  

---

### [CVE-2025-56218](CVE-2025-56218-saykino_CVE-2025-56218.md) 🟡 ✅

**名称:** CVE-2025-56218-SigningHub-Unrestricted File Upload  
**类型:** Unrestricted File Upload  
**风险:** 中危，可能导致钓鱼攻击和社会工程学攻击  
**投毒风险:** 10%  
**发现时间:** 2025-10-14  
**POC仓库:** [CVE-2025-56218](https://github.com/saykino/CVE-2025-56218)  

---

### [CVE-2025-7441](CVE-2025-7441-Pwdnx1337_CVE-2025-7441.md) 🔴 ✅

**名称:** CVE-2025-7441-StoryChief-Unauthenticated Arbitrary File Upload  
**类型:** Arbitrary File Upload  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-10-14  
**POC仓库:** [CVE-2025-7441](https://github.com/Pwdnx1337/CVE-2025-7441)  

---

### [CVE-2025-6554](CVE-2025-6554-jopraveen_CVE-2025-6554.md) 🔴 ✅

**名称:** CVE-2025-6554-Chrome-V8类型混淆  
**类型:** 类型混淆  
**风险:** 高危，允许远程攻击者通过精心制作的HTML页面执行任意读写操作  
**投毒风险:** 10%  
**发现时间:** 2025-10-14  
**POC仓库:** [CVE-2025-6554](https://github.com/jopraveen/CVE-2025-6554)  

---

### [CVE-2025-39682](CVE-2025-39682-khoatran107_cve-2025-39682.md) 🔴 ✅

**名称:** CVE-2025-39682-Linux Kernel TLS零长度记录处理漏洞  
**类型:** 内存破坏/提权  
**风险:** 高危，可能导致内核崩溃或权限提升  
**投毒风险:** 10%  
**发现时间:** 2025-10-14  
**POC仓库:** [cve-2025-39682](https://github.com/khoatran107/cve-2025-39682)  

---

### [CVE-2025-10720](CVE-2025-10720-lorenzocamilli_CVE-2025-10720-PoC.md) 🔴 ✅

**名称:** CVE-2025-10720-WP Private Content Plus-身份验证绕过  
**类型:** 身份验证绕过  
**风险:** 高危，可能导致未授权访问  
**投毒风险:** 0%  
**发现时间:** 2025-10-14  
**POC仓库:** [CVE-2025-10720-PoC](https://github.com/lorenzocamilli/CVE-2025-10720-PoC)  

---

### [CVE-2024-32444](CVE-2024-32444-rxerium_CVE-2024-32444.md) 🔴 ✅

**名称:** CVE-2024-32444 - WordPress RealHomes Theme Privilege Escalation  
**类型:** 权限提升  
**风险:** 高危，攻击者可获得管理员权限，控制网站  
**投毒风险:** 10%  
**发现时间:** 2025-10-14  
**POC仓库:** [CVE-2024-32444](https://github.com/rxerium/CVE-2024-32444)  

---

### [CVE-2024-12084](CVE-2024-12084-themirze_cve-2024-12084.md)  ✅

**名称:** CVE-2024-12084-Rsync-堆缓冲区溢出  
**类型:** 堆缓冲区溢出  
**风险:** 严重，可能导致远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-10-14  
**POC仓库:** [cve-2024-12084](https://github.com/themirze/cve-2024-12084)  

---

### [CVE-2024-12084](CVE-2024-12084-rxerium_CVE-2024-12084.md) 🔴 ✅

**名称:** CVE-2024-12084-rsync-堆缓冲区溢出  
**类型:** 堆缓冲区溢出  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-10-14  
**POC仓库:** [CVE-2024-12084](https://github.com/rxerium/CVE-2024-12084)  

---

### [CVE-2025-26465](CVE-2025-26465-dolutech_patch-manual-CVE-2025-26465-e-CVE-2025-26466.md) 🟡 

**名称:** CVE-2025-26465 & CVE-2025-26466 - OpenSSH 中间人攻击和DoS漏洞缓解脚本分析  
**类型:** 中间人攻击 & DoS缓解  
**风险:** 中危，可能导致SSH连接被窃听或服务不可用  
**投毒风险:** 10%  
**发现时间:** 2025-10-14  
**POC仓库:** [patch-manual-CVE-2025-26465-e-CVE-2025-26466](https://github.com/dolutech/patch-manual-CVE-2025-26465-e-CVE-2025-26466)  

---

### [CVE-2025-26465](CVE-2025-26465-rxerium_CVE-2025-26465.md) 🟡 ✅

**名称:** CVE-2025-26465-OpenSSH-中间人攻击  
**类型:** 中间人攻击 (MitM)  
**风险:** 中危，可能导致敏感信息泄露和会话劫持  
**投毒风险:** 0%  
**发现时间:** 2025-10-14  
**POC仓库:** [CVE-2025-26465](https://github.com/rxerium/CVE-2025-26465)  

---

### [CVE-2025-0994](CVE-2025-0994-rxerium_CVE-2025-0994.md) 🔴 ✅

**名称:** CVE-2025-0994-Trimble Cityworks-反序列化  
**类型:** 反序列化  
**风险:** 高危，允许已认证用户对客户的Microsoft IIS Web服务器执行远程代码执行攻击。  
**投毒风险:** 0%  
**发现时间:** 2025-10-14  
**POC仓库:** [CVE-2025-0994](https://github.com/rxerium/CVE-2025-0994)  

---

### [CVE-2025-24016](CVE-2025-24016-GloStarRx1_CVE-2025-24016.md) 🔴 ✅

**名称:** CVE-2025-24016-Wazuh-反序列化RCE  
**类型:** 反序列化漏洞  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-10-14  
**POC仓库:** [CVE-2025-24016](https://github.com/GloStarRx1/CVE-2025-24016)  

---

### [CVE-2025-24016](CVE-2025-24016-guinea-offensive-security_Wazuh-RCE.md) 🔴 ✅

**名称:** CVE-2025-24016 - Wazuh Server RCE  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-10-14  
**POC仓库:** [Wazuh-RCE](https://github.com/guinea-offensive-security/Wazuh-RCE)  

---

### [CVE-2023-40000](CVE-2023-40000-quantiom_litespeed-cache-xss-poc.md) 🔴 ✅

**名称:** CVE-2023-40000-LiteSpeed Cache-Stored XSS  
**类型:** Stored XSS  
**风险:** 高危，可能导致权限提升和敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-10-14  
**POC仓库:** [litespeed-cache-xss-poc](https://github.com/quantiom/litespeed-cache-xss-poc)  

---

### [CVE-2023-40000](CVE-2023-40000-iveresk_cve-2023-40000.md) 🔴 ✅

**名称:** CVE-2023-40000-LiteSpeed Cache-存储型XSS  
**类型:** 存储型XSS  
**风险:** 高危，可导致管理员账号被盗，恶意代码执行，网站内容篡改。  
**投毒风险:** 10%  
**发现时间:** 2025-10-14  
**POC仓库:** [cve-2023-40000](https://github.com/iveresk/cve-2023-40000)  

---

### [CVE-2023-40000](CVE-2023-40000-rxerium_CVE-2023-40000.md) 🔴 ✅

**名称:** CVE-2023-40000 - WordPress LiteSpeed Cache 存储型XSS漏洞  
**类型:** 存储型XSS (Stored XSS)  
**风险:** 高危，可能导致权限提升和网站控制  
**投毒风险:** 10%  
**发现时间:** 2025-10-14  
**POC仓库:** [CVE-2023-40000](https://github.com/rxerium/CVE-2023-40000)  

---

### [CVE-2025-25198](CVE-2025-25198-enzocipher_CVE-2025-25198-PoC.md) 🔴 

**名称:** CVE-2025-25198-mailcow-dockerized-密码重置投毒  
**类型:** URL重定向漏洞 (CWE-601)  
**风险:** 高危，可能导致账户接管  
**投毒风险:** 0%  
**发现时间:** 2025-10-14  
**POC仓库:** [CVE-2025-25198-PoC](https://github.com/enzocipher/CVE-2025-25198-PoC)  

---

### [CVE-2025-25198](CVE-2025-25198-Groppoxx_CVE-2025-25198-PoC.md) 🔴 ✅

**名称:** CVE-2025-25198-mailcow: dockerized-密码重置链接投毒  
**类型:** 密码重置链接投毒  
**风险:** 高危，可能导致账户接管  
**投毒风险:** 0%  
**发现时间:** 2025-10-14  
**POC仓库:** [CVE-2025-25198-PoC](https://github.com/Groppoxx/CVE-2025-25198-PoC)  

---

### [CVE-2017-12542](CVE-2017-12542-skelsec_CVE-2017-12542.md) 🔴 ✅

**名称:** CVE-2017-12542-HPE iLO 4-认证绕过与代码执行  
**类型:** 认证绕过与代码执行  
**风险:** 高危，可能导致系统完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-10-13  
**POC仓库:** [CVE-2017-12542](https://github.com/skelsec/CVE-2017-12542)  

---

### [CVE-2017-12542](CVE-2017-12542-sk1dish_ilo4-rce-vuln-scanner.md) 🔴 ✅

**名称:** CVE-2017-12542 - HPE iLO 4 身份验证绕过和代码执行  
**类型:** 身份验证绕过和代码执行  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-10-13  
**POC仓库:** [ilo4-rce-vuln-scanner](https://github.com/sk1dish/ilo4-rce-vuln-scanner)  

---

### [CVE-2017-12542](CVE-2017-12542-VijayShankar22_CVE-2017-12542.md) 🔴 ✅

**名称:** CVE-2017-12542-HP iLO 4-身份验证绕过和代码执行  
**类型:** 身份验证绕过和代码执行  
**风险:** 高危，允许未经授权的远程访问和控制服务器。  
**投毒风险:** 5%  
**发现时间:** 2025-10-13  
**POC仓库:** [CVE-2017-12542](https://github.com/VijayShankar22/CVE-2017-12542)  

---

### [CVE-2025-59489](CVE-2025-59489-AdriianFdz_Exploit-CVE-2025-59489.md) 🔴 

**名称:** CVE-2025-59489 Unity Runtime 参数注入  
**类型:** 参数注入  
**风险:** 高危，可能导致远程代码执行和信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-10-13  
**POC仓库:** [Exploit-CVE-2025-59489](https://github.com/AdriianFdz/Exploit-CVE-2025-59489)  

---

### [CVE-2024-39930](CVE-2024-39930-laachy_CVE-2024-39930-ptrace-detection-mitigation.md) 🔴 ✅

**名称:** CVE-2024-39930-Gogs-SSH参数注入导致远程代码执行  
**类型:** SSH参数注入  
**风险:** 高危，允许认证后的攻击者远程执行代码  
**投毒风险:** 5%  
**发现时间:** 2025-10-13  
**POC仓库:** [CVE-2024-39930-ptrace-detection-mitigation](https://github.com/laachy/CVE-2024-39930-ptrace-detection-mitigation)  

---

### [CVE-2025-39913](CVE-2025-39913-byteReaper77_CVE-2025-39913-.md) 🔴 ✅

**名称:** CVE-2025-39913 - Linux Kernel eBPF SOCKMAP UAF  
**类型:** Use-After-Free (UAF)  
**风险:** 高危，可能导致内核崩溃、权限提升甚至任意代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-10-13  
**POC仓库:** [CVE-2025-39913-](https://github.com/byteReaper77/CVE-2025-39913-)  

---

### [CVE-2025-61884](CVE-2025-61884-B1ack4sh_Blackash-CVE-2025-61884.md) 🔴 ✅

**名称:** CVE-2025-61884-Oracle Configurator-未授权数据访问  
**类型:** 未授权数据访问  
**风险:** 高危，可能导致敏感数据泄露  
**投毒风险:** 10%  
**发现时间:** 2025-10-13  
**POC仓库:** [Blackash-CVE-2025-61884](https://github.com/B1ack4sh/Blackash-CVE-2025-61884)  

---

### [CVE-2025-11171](CVE-2025-11171-SnailSploit_CVE-2025-11171---GitHub-Security-Advisory.md) 🟡 ✅

**名称:** CVE-2025-11171-Chartify-WordPress-Plugin-未授权访问  
**类型:** 未授权访问  
**风险:** 中危，可能导致插件设置被篡改  
**投毒风险:** 10%  
**发现时间:** 2025-10-13  
**POC仓库:** [CVE-2025-11171---GitHub-Security-Advisory](https://github.com/SnailSploit/CVE-2025-11171---GitHub-Security-Advisory)  

---

### [CVE-2024-43425](CVE-2024-43425-aayush256-sys_Moodle-authenticated-RCE.md) 🔴 ✅

**名称:** CVE-2024-43425-Moodle-RCE  
**类型:** 远程代码执行  
**风险:** 高危，允许攻击者在服务器上执行任意命令  
**投毒风险:** 10%  
**发现时间:** 2025-10-13  
**POC仓库:** [Moodle-authenticated-RCE](https://github.com/aayush256-sys/Moodle-authenticated-RCE)  

---

### [CVE-2024-43425](CVE-2024-43425-Tnot123_cve-2024-43425.md) 🔴 ✅

**名称:** CVE-2024-43425 - Moodle 远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-10-13  
**POC仓库:** [cve-2024-43425](https://github.com/Tnot123/cve-2024-43425)  

---

### [CVE-2018-14714](CVE-2018-14714-sunn1day_CVE-2018-14714-POC.md) 🔴 ✅

**名称:** CVE-2018-14714-ASUS RT-AC3200 命令注入  
**类型:** 命令注入  
**风险:** 高危，可能导致远程代码执行，完全控制路由器  
**投毒风险:** 0%  
**发现时间:** 2025-10-13  
**POC仓库:** [CVE-2018-14714-POC](https://github.com/sunn1day/CVE-2018-14714-POC)  

---

### [CVE-2018-14714](CVE-2018-14714-tin-z_CVE-2018-14714-POC.md) 🔴 ✅

**名称:** CVE-2018-14714-ASUS RT-AC3200 appGet.cgi 命令注入  
**类型:** 命令注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-10-13  
**POC仓库:** [CVE-2018-14714-POC](https://github.com/tin-z/CVE-2018-14714-POC)  

---

### [CVE-2018-14714](CVE-2018-14714-BreadSquad_TimeInjector.md) 🔴 ✅

**名称:** CVE-2018-14714-ASUS RT-AC3200-命令注入  
**类型:** 命令注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-10-13  
**POC仓库:** [TimeInjector](https://github.com/BreadSquad/TimeInjector)  

---

### [CVE-2018-14714](CVE-2018-14714-BTtea_CVE-2018-14714-RCE-exploit.md) 🔴 ✅

**名称:** CVE-2018-14714-ASUS RT-AC3200-命令注入  
**类型:** 命令注入  
**风险:** 高危，允许远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-10-13  
**POC仓库:** [CVE-2018-14714-RCE-exploit](https://github.com/BTtea/CVE-2018-14714-RCE-exploit)  

---

### [CVE-2025-61984](CVE-2025-61984-ThanhCT-CyX_Test-CVE-2025-61984.md) 🟡 ✅

**名称:** CVE-2025-61984-OpenSSH-命令注入  
**类型:** 命令注入  
**风险:** 中危，可能导致低权限用户执行任意命令  
**投毒风险:** 0%  
**发现时间:** 2025-10-13  
**POC仓库:** [Test-CVE-2025-61984](https://github.com/ThanhCT-CyX/Test-CVE-2025-61984)  

---

### [CVE-2025-39913](CVE-2025-39913-byteReaper77_CVE-2025-39913.md) 🟡 ✅

**名称:** CVE-2025-39913-Linux Kernel-TCP BPF内存泄漏  
**类型:** 内存泄漏  
**风险:** 中危，可能导致拒绝服务  
**投毒风险:** 10%  
**发现时间:** 2025-10-12  
**POC仓库:** [CVE-2025-39913](https://github.com/byteReaper77/CVE-2025-39913)  

---

### [CVE-2025-6202](CVE-2025-6202-demining_Phoenix-Rowhammer-Attack-CVE-2025-6202.md) 🔴 ✅

**名称:** CVE-2025-6202 - SK Hynix DDR5 Rowhammer  
**类型:** 硬件缺陷 - Rowhammer  
**风险:** 高危，可能导致硬件完整性破坏，系统安全受损  
**投毒风险:** 5%  
**发现时间:** 2025-10-12  
**POC仓库:** [Phoenix-Rowhammer-Attack-CVE-2025-6202](https://github.com/demining/Phoenix-Rowhammer-Attack-CVE-2025-6202)  

---

### [CVE-2022-25844](CVE-2022-25844-ssolucionesdefontaneria-debug_CVE-2022-25844.md) 🟡 

**名称:** CVE-2022-25844 - angular Regular Expression Denial of Service (ReDoS)  
**类型:** ReDoS  
**风险:** 中危，可能导致服务拒绝  
**投毒风险:** 30%  
**发现时间:** 2025-10-12  
**POC仓库:** [CVE-2022-25844](https://github.com/ssolucionesdefontaneria-debug/CVE-2022-25844)  

---

### [CVE-2025-10184](CVE-2025-10184-ENGWes_ColorOS-CVE-2025-10184.md) 🔴 ✅

**名称:** CVE-2025-10184-OnePlus OxygenOS Telephony provider 权限绕过  
**类型:** 权限绕过/SQL注入  
**风险:** 高危，可能导致SMS/MMS数据泄露及MFA绕过  
**投毒风险:** 70%  
**发现时间:** 2025-10-12  
**POC仓库:** [ColorOS-CVE-2025-10184](https://github.com/ENGWes/ColorOS-CVE-2025-10184)  

---

### [CVE-2022-22963](CVE-2022-22963-xmqaq_CVE-2022-22963.md) 🔴 ✅

**名称:** CVE-2022-22963 Spring Cloud Function SpEL表达式注入  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行和敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-10-12  
**POC仓库:** [CVE-2022-22963](https://github.com/xmqaq/CVE-2022-22963)  

---

### [CVE-2024-27304](CVE-2024-27304-roaris_CVE-2024-27304-PoC.md) 🔴 ✅

**名称:** CVE-2024-27304-pgx-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-10-12  
**POC仓库:** [CVE-2024-27304-PoC](https://github.com/roaris/CVE-2024-27304-PoC)  

---

### [CVE-2025-21298](CVE-2025-21298-Arkha-Corvus_LetsDefend-SOC336-Windows-OLE-Zero-Click-RCE-Exploitation-Detected-CVE-2025-21298-.md) 🔴 ✅

**名称:** CVE-2025-21298 - Windows OLE 远程代码执行漏洞  
**类型:** 远程代码执行  
**风险:** 高危，可被利用实现远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-10-12  
**POC仓库:** [LetsDefend-SOC336-Windows-OLE-Zero-Click-RCE-Exploitation-Detected-CVE-2025-21298-](https://github.com/Arkha-Corvus/LetsDefend-SOC336-Windows-OLE-Zero-Click-RCE-Exploitation-Detected-CVE-2025-21298-)  

---

### [CVE-2025-32463](CVE-2025-32463-cyberajju_CVE-2025-32463.md) 🔴 ✅

**名称:** CVE-2025-32463-Sudo-本地提权  
**类型:** 本地提权  
**风险:** 高危，本地用户可以获得root权限  
**投毒风险:** 10%  
**发现时间:** 2025-10-12  
**POC仓库:** [CVE-2025-32463](https://github.com/cyberajju/CVE-2025-32463)  

---

### [CVE-2023-29360](CVE-2023-29360-Nero22k_cve-2023-29360.md) 🔴 ✅

**名称:** CVE-2023-29360 - Microsoft Streaming Service Elevation of Privilege  
**类型:** 权限提升  
**风险:** 高危，本地权限提升  
**投毒风险:** 10%  
**发现时间:** 2025-10-12  
**POC仓库:** [cve-2023-29360](https://github.com/Nero22k/cve-2023-29360)  

---

### [CVE-2023-29360](CVE-2023-29360-0xDivyanshu-new_CVE-2023-29360.md) 🔴 ✅

**名称:** CVE-2023-29360-Microsoft Streaming Service Elevation of Privilege Vulnerability  
**类型:** 特权提升  
**风险:** 高危，可能导致本地权限提升  
**投毒风险:** 0%  
**发现时间:** 2025-10-12  
**POC仓库:** [CVE-2023-29360](https://github.com/0xDivyanshu-new/CVE-2023-29360)  

---

### [CVE-2023-29360](CVE-2023-29360-Scottman625_CVE-2023-29360.md) 🔴 ✅

**名称:** CVE-2023-29360 Microsoft Streaming Service Elevation of Privilege Vulnerability  
**类型:** 特权提升  
**风险:** 高危，可导致本地权限提升  
**投毒风险:** 10%  
**发现时间:** 2025-10-12  
**POC仓库:** [CVE-2023-29360](https://github.com/Scottman625/CVE-2023-29360)  

---

### [CVE-2022-37122](CVE-2022-37122-bughuntar_CVE-2022-37122-Exploit.md) 🔴 ✅

**名称:** CVE-2022-37122 Carel pCOWeb HVAC BACnet Gateway 任意文件读取漏洞  
**类型:** 任意文件读取  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-10-12  
**POC仓库:** [CVE-2022-37122-Exploit](https://github.com/bughuntar/CVE-2022-37122-Exploit)  

---

### [CVE-2024-28397](CVE-2024-28397-0xPadme_CVE-2024-28397-Reverse-Shell.md) 🔴 ✅

**名称:** CVE-2024-28397-js2py-Sandbox-Escape  
**类型:** 代码注入/沙箱逃逸  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-10-12  
**POC仓库:** [CVE-2024-28397-Reverse-Shell](https://github.com/0xPadme/CVE-2024-28397-Reverse-Shell)  

---

### [CVE-2025-11371](CVE-2025-11371-callinston_CVE-2025-11371.md) 🔴 ✅

**名称:** CVE-2025-11371-Gladinet CentreStack/TrioFox-LFI  
**类型:** 本地文件包含 (LFI)  
**风险:** 高危，可能导致敏感信息泄露，配合其他漏洞可能导致远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-10-11  
**POC仓库:** [CVE-2025-11371](https://github.com/callinston/CVE-2025-11371)  

---

### [CVE-2025-58434](CVE-2025-58434-nltt-br_CVE-2025-58434-CVE-2025-61687-chain-.md)  ✅

**名称:** CVE-2025-58434-FlowiseAI-账户接管和RCE  
**类型:** 账户接管和远程代码执行(RCE)  
**风险:** 严重，可能导致完全账户接管和服务器控制  
**投毒风险:** 0%  
**发现时间:** 2025-10-11  
**POC仓库:** [CVE-2025-58434-CVE-2025-61687-chain-](https://github.com/nltt-br/CVE-2025-58434-CVE-2025-61687-chain-)  

---

### [CVE-2025-32463](CVE-2025-32463-cybershaolin47_CVE-2025-32463_POC.md) 🔴 ✅

**名称:** CVE-2025-32463-Sudo-本地提权  
**类型:** 本地提权  
**风险:** 高危，允许本地用户获取root权限  
**投毒风险:** 10%  
**发现时间:** 2025-10-11  
**POC仓库:** [CVE-2025-32463_POC](https://github.com/cybershaolin47/CVE-2025-32463_POC)  

---

### [CVE-2024-58239](CVE-2024-58239-khoatran107_cve-2024-58239.md)  ✅

**名称:** CVE-2024-58239  
**类型:** TLS处理错误  
**风险:** 可能导致拒绝服务或信息泄露 (取决于具体利用方式)  
**投毒风险:** 10%  
**发现时间:** 2025-10-11  
**POC仓库:** [cve-2024-58239](https://github.com/khoatran107/cve-2024-58239)  

---

### [CVE-2025-59489](CVE-2025-59489-taptap_cve-2025-59489.md) 🔴 

**名称:** CVE-2025-59489-Unity-参数注入  
**类型:** 参数注入  
**风险:** 高危，可能导致任意代码执行和信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-10-11  
**POC仓库:** [cve-2025-59489](https://github.com/taptap/cve-2025-59489)  

---

### [CVE-2025-49844](CVE-2025-49844-imbas007_CVE-2025-49844-Vulnerability-Scanner.md) 🔴 ✅

**名称:** CVE-2025-49844-Redis Lua Use-After-Free RCE  
**类型:** Use-After-Free  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-10-11  
**POC仓库:** [CVE-2025-49844-Vulnerability-Scanner](https://github.com/imbas007/CVE-2025-49844-Vulnerability-Scanner)  

---

### [CVE-2025-61777](CVE-2025-61777-0x0w1z_CVE-2025-61777.md) 🔴 ✅

**名称:** CVE-2025-61777-flagForge-未授权API访问  
**类型:** 未授权访问  
**风险:** 高危，可能导致敏感信息泄露、数据污染和权限提升  
**投毒风险:** 0%  
**发现时间:** 2025-10-11  
**POC仓库:** [CVE-2025-61777](https://github.com/0x0w1z/CVE-2025-61777)  

---

### [CVE-2025-32421](CVE-2025-32421-hidesec_CVE-2025-32421.md) 🔴 ✅

**名称:** CVE-2025-32421 Next.js Race Condition to Cache Poisoning + XSS  
**类型:** 缓存投毒 + XSS  
**风险:** 高危，可能导致敏感信息泄露和任意代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-10-11  
**POC仓库:** [CVE-2025-32421](https://github.com/hidesec/CVE-2025-32421)  

---

### [CVE-2025-59246](CVE-2025-59246-callinston_CVE-2025-59246.md) 🔴 

**名称:** CVE-2025-59246 - Azure Entra ID 权限提升漏洞  
**类型:** 权限提升  
**风险:** 高危，可能导致完全控制组织身份管理和Azure资源  
**投毒风险:** 75%  
**发现时间:** 2025-10-11  
**POC仓库:** [CVE-2025-59246](https://github.com/callinston/CVE-2025-59246)  

---

### [CVE-2025-54793](CVE-2025-54793-Bhuvanesh-Murdoch2005_ict279-cve-2025-54793.md) 🟡 ✅

**名称:** CVE-2025-54793-Astro-Open Redirect  
**类型:** Open Redirect  
**风险:** 中危，可能导致用户重定向到恶意网站，增加钓鱼和社会工程攻击的风险  
**投毒风险:** 5%  
**发现时间:** 2025-10-11  
**POC仓库:** [ict279-cve-2025-54793](https://github.com/Bhuvanesh-Murdoch2005/ict279-cve-2025-54793)  

---

### [CVE-2025-59246](CVE-2025-59246-Mpokes_CVE-2025-59246-Exploit.md) 🔴 ✅

**名称:** CVE-2025-59246 Azure Entra ID 权限提升漏洞  
**类型:** 权限提升  
**风险:** 极高危，可能导致租户完全受损、数据泄露和服务中断  
**投毒风险:** 70%  
**发现时间:** 2025-10-10  
**POC仓库:** [CVE-2025-59246-Exploit](https://github.com/Mpokes/CVE-2025-59246-Exploit)  

---

### [CVE-2025-61882](CVE-2025-61882-zerozenxlabs_CVE-2025-61882-Oracle-EBS.md) 🔴 ✅

**名称:** CVE-2025-61882-Oracle Concurrent Processing-SSRF/RCE  
**类型:** 服务器端请求伪造(SSRF)/远程代码执行(RCE)  
**风险:** 高危，可导致服务器接管  
**投毒风险:** 10%  
**发现时间:** 2025-10-10  
**POC仓库:** [CVE-2025-61882-Oracle-EBS](https://github.com/zerozenxlabs/CVE-2025-61882-Oracle-EBS)  

---

### [CVE-2025-41089](CVE-2025-41089-Marinafabregat_CVE-2025-41089.md) 🟡 ✅

**名称:** CVE-2025-41089-Xibo CMS-Reflected XSS  
**类型:** Reflected XSS  
**风险:** 中危，可能导致会话劫持、恶意重定向等  
**投毒风险:** 0%  
**发现时间:** 2025-10-10  
**POC仓库:** [CVE-2025-41089](https://github.com/Marinafabregat/CVE-2025-41089)  

---

### [CVE-2025-60374](CVE-2025-60374-ajansha_CVE-2025-60374.md) 🔴 ✅

**名称:** CVE-2025-60374 - Perfex CRM Chatbot 存储型XSS  
**类型:** 存储型跨站脚本 (XSS)  
**风险:** 高危，可能导致会话劫持、账户接管、权限提升、数据窃取和网络钓鱼  
**投毒风险:** 0%  
**发现时间:** 2025-10-10  
**POC仓库:** [CVE-2025-60374](https://github.com/ajansha/CVE-2025-60374)  

---

### [CVE-2024-38856](CVE-2024-38856-emanueldosreis_CVE-2024-38856.md) 🔴 ✅

**名称:** CVE-2024-38856-Apache OFBiz-未授权访问导致代码执行  
**类型:** 未授权访问  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-10-10  
**POC仓库:** [CVE-2024-38856](https://github.com/emanueldosreis/CVE-2024-38856)  

---

### [CVE-2024-38856](CVE-2024-38856-Hex00-0x4_CVE-2024-38856-Apache-OFBiz.md) 🔴 ✅

**名称:** CVE-2024-38856-Apache OFBiz-未授权访问  
**类型:** 未授权访问  
**风险:** 高危，可能导致信息泄露和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-10-10  
**POC仓库:** [CVE-2024-38856-Apache-OFBiz](https://github.com/Hex00-0x4/CVE-2024-38856-Apache-OFBiz)  

---

### [CVE-2025-41088](CVE-2025-41088-Marinafabregat_CVE-2025-41088-Stored-XSS-in-Xibo-Signage-s-Xibo.md) 🟡 ✅

**名称:** CVE-2025-41088-Xibo CMS-存储型XSS  
**类型:** 存储型XSS  
**风险:** 中危，可能导致信息泄露和会话劫持  
**投毒风险:** 0%  
**发现时间:** 2025-10-10  
**POC仓库:** [CVE-2025-41088-Stored-XSS-in-Xibo-Signage-s-Xibo](https://github.com/Marinafabregat/CVE-2025-41088-Stored-XSS-in-Xibo-Signage-s-Xibo)  

---

### [CVE-2025-11371](CVE-2025-11371-rxerium_CVE-2025-11371.md) 🟡 ✅

**名称:** CVE-2025-11371-Gladinet CentreStack and TrioFox-本地文件包含  
**类型:** 本地文件包含(LFI)  
**风险:** 中危，可能导致敏感文件泄露  
**投毒风险:** 0%  
**发现时间:** 2025-10-10  
**POC仓库:** [CVE-2025-11371](https://github.com/rxerium/CVE-2025-11371)  

---

### [CVE-2024-21262](CVE-2024-21262-Noah4Puppy_CVE-2024-21262.md) 🟡 

**名称:** CVE-2024-21262-MySQL Connectors  
**类型:** 权限绕过/DoS  
**风险:** 中危，可能导致数据篡改和部分拒绝服务  
**投毒风险:** 5%  
**发现时间:** 2025-10-10  
**POC仓库:** [CVE-2024-21262](https://github.com/Noah4Puppy/CVE-2024-21262)  

---

### [CVE-2025-11449](CVE-2025-11449-DanielMadsenDK_ServiceNow-CVE-2025-11449-CVE-2025-11450-Mitigation-Script.md) 🟡 ✅

**名称:** CVE-2025-11449-ServiceNow AI Platform-Reflected XSS  
**类型:** Reflected XSS  
**风险:** 中危，可能导致用户浏览器中执行任意代码，窃取敏感信息或进行恶意操作  
**投毒风险:** 0%  
**发现时间:** 2025-10-10  
**POC仓库:** [ServiceNow-CVE-2025-11449-CVE-2025-11450-Mitigation-Script](https://github.com/DanielMadsenDK/ServiceNow-CVE-2025-11449-CVE-2025-11450-Mitigation-Script)  

---

### [CVE-2025-60375](CVE-2025-60375-ajansha_CVE-2025-60375.md) 🔴 ✅

**名称:** CVE-2025-60375 - Perfex CRM 身份验证绕过  
**类型:** 身份验证绕过  
**风险:** 高危，可能导致未授权访问、数据泄露和完全系统控制  
**投毒风险:** 5%  
**发现时间:** 2025-10-10  
**POC仓库:** [CVE-2025-60375](https://github.com/ajansha/CVE-2025-60375)  

---

### [CVE-2025-5947](CVE-2025-5947-M4rgs_CVE-2025-5947_Exploit.md) 🔴 ✅

**名称:** CVE-2025-5947 - Service Finder Bookings <= 6.0 Authentication Bypass  
**类型:** 身份验证绕过  
**风险:** 高危，可导致任意用户（包括管理员）权限获取  
**投毒风险:** 10%  
**发现时间:** 2025-10-10  
**POC仓库:** [CVE-2025-5947_Exploit](https://github.com/M4rgs/CVE-2025-5947_Exploit)  

---

### [CVE-2025-60880](CVE-2025-60880-Shenal01_CVE-2025-60880.md) 🔴 ✅

**名称:** CVE-2025-60880 - Bagisto Admin Panel Stored XSS  
**类型:** Stored XSS  
**风险:** 高危，可能导致会话劫持、数据窃取和未经授权的操作  
**投毒风险:** 0%  
**发现时间:** 2025-10-10  
**POC仓库:** [CVE-2025-60880](https://github.com/Shenal01/CVE-2025-60880)  

---

### [CVE-2024-38856](CVE-2024-38856-ThatNotEasy_CVE-2024-38856.md) 🔴 ✅

**名称:** CVE-2024-38856-Apache OFBiz-未授权访问导致RCE  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-10-10  
**POC仓库:** [CVE-2024-38856](https://github.com/ThatNotEasy/CVE-2024-38856)  

---

### [CVE-2024-38856](CVE-2024-38856-Praison001_CVE-2024-38856-ApacheOfBiz.md) 🔴 ✅

**名称:** CVE-2024-38856-Apache OFBiz-未授权访问漏洞  
**类型:** 未授权访问/远程代码执行  
**风险:** 高危，可能导致远程代码执行和数据泄露  
**投毒风险:** 10%  
**发现时间:** 2025-10-10  
**POC仓库:** [CVE-2024-38856-ApacheOfBiz](https://github.com/Praison001/CVE-2024-38856-ApacheOfBiz)  

---

### [CVE-2024-38856](CVE-2024-38856-0x20c_CVE-2024-38856-EXP.md) 🔴 ✅

**名称:** CVE-2024-38856-Apache OFBiz-RCE  
**类型:** 远程代码执行  
**风险:** 高危，未经身份验证的远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-10-10  
**POC仓库:** [CVE-2024-38856-EXP](https://github.com/0x20c/CVE-2024-38856-EXP)  

---

### [CVE-2024-38856](CVE-2024-38856-BBD-YZZ_CVE-2024-38856-RCE.md) 🔴 ✅

**名称:** CVE-2024-38856-Apache OFBiz-不正确的授权  
**类型:** 不正确的授权  
**风险:** 高危，可能导致信息泄露、数据篡改甚至远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-10-10  
**POC仓库:** [CVE-2024-38856-RCE](https://github.com/BBD-YZZ/CVE-2024-38856-RCE)  

---

### [CVE-2024-38856](CVE-2024-38856-securelayer7_CVE-2024-38856_Scanner.md) 🔴 ✅

**名称:** CVE-2024-38856-Apache OFBiz-未授权访问  
**类型:** 未授权访问  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-10-10  
**POC仓库:** [CVE-2024-38856_Scanner](https://github.com/securelayer7/CVE-2024-38856_Scanner)  

---

### [CVE-2024-38856](CVE-2024-38856-XiaomingX_cve-2024-38856-poc.md) 🔴 ✅

**名称:** CVE-2024-38856-Apache OFBiz-未授权屏幕渲染代码执行  
**类型:** 未授权访问/远程代码执行  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-10-10  
**POC仓库:** [cve-2024-38856-poc](https://github.com/XiaomingX/cve-2024-38856-poc)  

---

### [CVE-2024-38856](CVE-2024-38856-FakesiteSecurity_CVE-2024-38856_Scen.md) 🔴 ✅

**名称:** CVE-2024-38856-Apache OFBiz-未授权屏幕渲染代码执行  
**类型:** 未授权访问/远程代码执行  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-10-10  
**POC仓库:** [CVE-2024-38856_Scen](https://github.com/FakesiteSecurity/CVE-2024-38856_Scen)  

---

### [CVE-2024-38856](CVE-2024-38856-AlissonFaoli_Apache-OFBiz-Exploit.md) 🔴 ✅

**名称:** CVE-2024-38856-Apache OFBiz-未授权RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 5%  
**发现时间:** 2025-10-10  
**POC仓库:** [Apache-OFBiz-Exploit](https://github.com/AlissonFaoli/Apache-OFBiz-Exploit)  

---

### [CVE-2025-2539](CVE-2025-2539-AlvaXPloit_CVE-2025-2539.md) 🔴 ✅

**名称:** CVE-2025-2539-File Away-任意文件读取  
**类型:** 任意文件读取  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-10-10  
**POC仓库:** [CVE-2025-2539](https://github.com/AlvaXPloit/CVE-2025-2539)  

---

### [CVE-2025-60378](CVE-2025-60378-ajansha_CVE-2025-60378.md) 🔴 ✅

**名称:** CVE-2025-60378-RISE-Ultimate-Project-Manager-CRM-Stored-HTML注入  
**类型:** Stored HTML Injection  
**风险:** 高危，可能导致大规模钓鱼、BEC和恶意软件传播  
**投毒风险:** 5%  
**发现时间:** 2025-10-09  
**POC仓库:** [CVE-2025-60378](https://github.com/ajansha/CVE-2025-60378)  

---

### [CVE-2025-55903](CVE-2025-55903-ajansha_CVE-2025-55903.md) 🟡 ✅

**名称:** CVE-2025-55903 - Perfex CRM Stored HTML Injection  
**类型:** Stored HTML Injection  
**风险:** 中危，可能导致XSS攻击，窃取用户凭证或进行恶意操作  
**投毒风险:** 10%  
**发现时间:** 2025-10-09  
**POC仓库:** [CVE-2025-55903](https://github.com/ajansha/CVE-2025-55903)  

---

### [CVE-2025-61319](CVE-2025-61319-AmalJafarzade_CVE-2025-61319.md) 🔴 ✅

**名称:** CVE-2025-61319-ReNgine-Stored XSS  
**类型:** Stored XSS  
**风险:** 高危，可能导致会话劫持、UI篡改和未经授权的操作  
**投毒风险:** 10%  
**发现时间:** 2025-10-09  
**POC仓库:** [CVE-2025-61319](https://github.com/AmalJafarzade/CVE-2025-61319)  

---

### [CVE-2025-4476](CVE-2025-4476-soltanali0_CVE-2025-4476-Exploit.md) 🟡 ✅

**名称:** CVE-2025-4476-Libsoup-空指针解引用  
**类型:** 空指针解引用  
**风险:** 中危，可能导致拒绝服务  
**投毒风险:** 10%  
**发现时间:** 2025-10-09  
**POC仓库:** [CVE-2025-4476-Exploit](https://github.com/soltanali0/CVE-2025-4476-Exploit)  

---

### [CVE-2025-8088](CVE-2025-8088-tookATE_CVE-2025-8088.md) 🔴 ✅

**名称:** CVE-2025-8088 WinRAR Path Traversal  
**类型:** Path Traversal  
**风险:** 高危，允许攻击者执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-10-09  
**POC仓库:** [CVE-2025-8088](https://github.com/tookATE/CVE-2025-8088)  

---

### [CVE-2025-60375](CVE-2025-60375-AhamedYaseen03_CVE-2025-60375.md) 🔴 ✅

**名称:** CVE-2025-60375 - PerfexCRM Authentication Bypass  
**类型:** Authentication Bypass / Incorrect Access Control  
**风险:** 高危，可导致未授权访问，包括管理员权限  
**投毒风险:** 0%  
**发现时间:** 2025-10-09  
**POC仓库:** [CVE-2025-60375](https://github.com/AhamedYaseen03/CVE-2025-60375)  

---

### [CVE-2023-50164](CVE-2023-50164-hybinn_CVE-2023-50164.md) 🔴 ✅

**名称:** CVE-2023-50164 Apache Struts 文件上传目录遍历漏洞  
**类型:** 文件上传目录遍历  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-10-09  
**POC仓库:** [CVE-2023-50164](https://github.com/hybinn/CVE-2023-50164)  

---

### [CVE-2023-21554](CVE-2023-21554-Rahul-Thakur7_CVE-2023-21554.md) 🔴 ✅

**名称:** CVE-2023-21554-Microsoft Message Queuing (MSMQ) 远程代码执行漏洞  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-10-09  
**POC仓库:** [CVE-2023-21554](https://github.com/Rahul-Thakur7/CVE-2023-21554)  

---

### [CVE-2023-21554](CVE-2023-21554-zoemurmure_CVE-2023-21554-PoC.md) 🔴 ✅

**名称:** CVE-2023-21554-Microsoft Message Queuing (MSMQ) Remote Code Execution Vulnerability  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-10-09  
**POC仓库:** [CVE-2023-21554-PoC](https://github.com/zoemurmure/CVE-2023-21554-PoC)  

---

### [CVE-2023-21554](CVE-2023-21554-3tternp_CVE-2023-21554.md) 🔴 ✅

**名称:** CVE-2023-21554-Microsoft Message Queuing (MSMQ) 远程代码执行漏洞  
**类型:** 远程代码执行  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-10-09  
**POC仓库:** [CVE-2023-21554](https://github.com/3tternp/CVE-2023-21554)  

---

### [CVE-2023-21554](CVE-2023-21554-leongxudong_MSMQ-Vulnerability.md) 🔴 ✅

**名称:** CVE-2023-21554 - Microsoft Message Queuing (MSMQ) 远程代码执行漏洞  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行和系统控制  
**投毒风险:** 10%  
**发现时间:** 2025-10-09  
**POC仓库:** [MSMQ-Vulnerability](https://github.com/leongxudong/MSMQ-Vulnerability)  

---

### [CVE-2023-21554](CVE-2023-21554-shootweb_CVE-2023-21554.md) 🔴 ✅

**名称:** CVE-2023-21554-MSMQ远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可被未经身份验证的攻击者利用  
**投毒风险:** 5%  
**发现时间:** 2025-10-09  
**POC仓库:** [CVE-2023-21554](https://github.com/shootweb/CVE-2023-21554)  

---

### [CVE-2025-49844](CVE-2025-49844-Mufti22_CVE-2025-49844-RediShell-Vulnerability-Scanner.md) 🔴 ✅

**名称:** CVE-2025-49844-Redis-Lua Use-After-Free  
**类型:** Use-After-Free  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-10-09  
**POC仓库:** [CVE-2025-49844-RediShell-Vulnerability-Scanner](https://github.com/Mufti22/CVE-2025-49844-RediShell-Vulnerability-Scanner)  

---

### [CVE-2024-32113](CVE-2024-32113-Mr-xn_CVE-2024-32113.md) 🔴 ✅

**名称:** CVE-2024-32113-Apache OFBiz-路径遍历导致RCE  
**类型:** 路径遍历导致RCE  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-10-09  
**POC仓库:** [CVE-2024-32113](https://github.com/Mr-xn/CVE-2024-32113)  

---

### [CVE-2024-32113](CVE-2024-32113-RacerZ-fighting_CVE-2024-32113-POC.md) 🔴 ✅

**名称:** CVE-2024-32113-Apache OFBiz-路径遍历导致RCE  
**类型:** 路径遍历  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-10-09  
**POC仓库:** [CVE-2024-32113-POC](https://github.com/RacerZ-fighting/CVE-2024-32113-POC)  

---

### [CVE-2024-32113](CVE-2024-32113-YongYe-Security_CVE-2024-32113.md) 🔴 ✅

**名称:** CVE-2024-32113 Apache OFBiz 路径遍历导致RCE  
**类型:** 路径遍历/远程代码执行  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-10-09  
**POC仓库:** [CVE-2024-32113](https://github.com/YongYe-Security/CVE-2024-32113)  

---

### [CVE-2024-32113](CVE-2024-32113-guinea-offensive-security_Ofbiz-RCE.md) 🔴 ✅

**名称:** CVE-2024-32113 - Apache OFBiz 路径遍历导致RCE  
**类型:** 路径遍历导致远程代码执行 (Path Traversal to RCE)  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-10-09  
**POC仓库:** [Ofbiz-RCE](https://github.com/guinea-offensive-security/Ofbiz-RCE)  

---

### [CVE-2024-32113](CVE-2024-32113-luizgaf_CVE-2024-32113-Apache-OFBiz-18.12.13-Exploit.md) 🔴 ✅

**名称:** CVE-2024-32113-Apache-OFBiz-路径遍历导致RCE  
**类型:** 路径遍历  
**风险:** 高危，可能导致任意文件读取和远程代码执行  
**投毒风险:** 95%  
**发现时间:** 2025-10-09  
**POC仓库:** [CVE-2024-32113-Apache-OFBiz-18.12.13-Exploit](https://github.com/luizgaf/CVE-2024-32113-Apache-OFBiz-18.12.13-Exploit)  

---

### [CVE-2025-49844](CVE-2025-49844-YuanBenSir_CVE-2025-49844_POC.md) 🔴 ✅

**名称:** CVE-2025-49844-Redis-Lua Use-After-Free  
**类型:** Use-After-Free  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-10-09  
**POC仓库:** [CVE-2025-49844_POC](https://github.com/YuanBenSir/CVE-2025-49844_POC)  

---

### [CVE-2023-42793](CVE-2023-42793-syorik_CVE-2023-42793-poc.md)  ✅

**名称:** CVE-2023-42793-JetBrains TeamCity-RCE  
**类型:** 远程代码执行  
**风险:** 严重，未授权远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-10-09  
**POC仓库:** [CVE-2023-42793-poc](https://github.com/syorik/CVE-2023-42793-poc)  

---

### [CVE-2025-32463](CVE-2025-32463-shazed-x_CVE-2025-32463.md) 🔴 ✅

**名称:** CVE-2025-32463 Sudo 本地提权漏洞  
**类型:** 本地提权  
**风险:** 高危，本地用户可获得root权限  
**投毒风险:** 0%  
**发现时间:** 2025-10-09  
**POC仓库:** [CVE-2025-32463](https://github.com/shazed-x/CVE-2025-32463)  

---

### [CVE-2025-49844](CVE-2025-49844-Yuri08loveElaina_CVE-2025-49844.md) 🔴 ✅

**名称:** CVE-2025-49844 - Redis Lua Use-After-Free Remote Code Execution  
**类型:** Use-After-Free  
**风险:** Critical，远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-10-09  
**POC仓库:** [CVE-2025-49844](https://github.com/Yuri08loveElaina/CVE-2025-49844)  

---

### [CVE-2025-32463](CVE-2025-32463-ricardomaia_CVE-2025-32463.md) 🔴 

**名称:** CVE-2025-32463-Sudo-Chroot-Privilege-Escalation  
**类型:** 权限提升  
**风险:** 高危，本地用户可提升至root权限  
**投毒风险:** 5%  
**发现时间:** 2025-10-09  
**POC仓库:** [CVE-2025-32463](https://github.com/ricardomaia/CVE-2025-32463)  

---

### [CVE-2025-32463](CVE-2025-32463-0x3c4dfa1_CVE-2025-32463.md) 🔴 ✅

**名称:** CVE-2025-32463-Sudo-Chroot权限提升  
**类型:** 权限提升  
**风险:** 高危，本地用户可获取root权限  
**投毒风险:** 10%  
**发现时间:** 2025-10-08  
**POC仓库:** [CVE-2025-32463](https://github.com/0x3c4dfa1/CVE-2025-32463)  

---

### [CVE-2025-10585](CVE-2025-10585-samus4vic_CVE-2025-10585-The-Chrome-V8-Zero-Day.md) 🔴 

**名称:** CVE-2025-10585-Chrome-V8类型混淆漏洞  
**类型:** 类型混淆  
**风险:** 高危，可能导致堆损坏和远程代码执行  
**投毒风险:** 85%  
**发现时间:** 2025-10-08  
**POC仓库:** [CVE-2025-10585-The-Chrome-V8-Zero-Day](https://github.com/samus4vic/CVE-2025-10585-The-Chrome-V8-Zero-Day)  

---

### [CVE-2025-57833](CVE-2025-57833-ianoboyle_CVE-2025-57833.md) 🔴 ✅

**名称:** CVE-2025-57833-Django-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露和未经授权的数据访问  
**投毒风险:** 5%  
**发现时间:** 2025-10-08  
**POC仓库:** [CVE-2025-57833](https://github.com/ianoboyle/CVE-2025-57833)  

---

### [CVE-2025-38561](CVE-2025-38561-toshithh_CVE-2025-38561.md) 🔴 ✅

**名称:** CVE-2025-38561-ksmbd-竞态条件  
**类型:** 竞态条件  
**风险:** 高危，可能导致拒绝服务或代码执行（具体取决于竞态条件如何被利用）  
**投毒风险:** 5%  
**发现时间:** 2025-10-08  
**POC仓库:** [CVE-2025-38561](https://github.com/toshithh/CVE-2025-38561)  

---

### [CVE-2025-37947](CVE-2025-37947-doyensec_KSMBD-CVE-2025-37947.md) 🔴 ✅

**名称:** CVE-2025-37947-Linux Kernel-ksmbd Out-of-bounds Write  
**类型:** Out-of-bounds Write  
**风险:** 高危，可能导致权限提升、拒绝服务或系统崩溃  
**投毒风险:** 10%  
**发现时间:** 2025-10-08  
**POC仓库:** [KSMBD-CVE-2025-37947](https://github.com/doyensec/KSMBD-CVE-2025-37947)  

---

### [CVE-2025-10353](CVE-2025-10353-ivansmc00_CVE-2025-10353.md) 🔴 ✅

**名称:** CVE-2025-10353-Melis Platform-RCE  
**类型:** 远程代码执行  
**风险:** 高危，允许未经身份验证的远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-10-08  
**POC仓库:** [CVE-2025-10353](https://github.com/ivansmc00/CVE-2025-10353)  

---

### [CVE-2025-49844](CVE-2025-49844-raminfp_redis_exploit.md) 🔴 ✅

**名称:** CVE-2025-49844 Redis Lua Use-After-Free Remote Code Execution  
**类型:** Use-After-Free  
**风险:** Critical，远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-10-08  
**POC仓库:** [redis_exploit](https://github.com/raminfp/redis_exploit)  

---

### [CVE-2025-49844](CVE-2025-49844-srozb_reditrap.md) 🔴 ✅

**名称:** CVE-2025-49844 Redis Lua Use-After-Free 漏洞  
**类型:** 使用后释放漏洞 (Use-After-Free)  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-10-08  
**POC仓库:** [reditrap](https://github.com/srozb/reditrap)  

---

### [CVE-2025-49844](CVE-2025-49844-pedrorichil_CVE-2025-49844.md) 🔴 ✅

**名称:** CVE-2025-49844-Redis-Lua Use-After-Free  
**类型:** Use-After-Free  
**风险:** 高危，远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-10-08  
**POC仓库:** [CVE-2025-49844](https://github.com/pedrorichil/CVE-2025-49844)  

---

### [CVE-2008-5161](CVE-2008-5161-talha3117_OpenSSH-4.7p1-CVE-2008-5161-Exploit.md) 🟡 ✅

**名称:** CVE-2008-5161 OpenSSH CBC 信息泄露漏洞利用辅助脚本  
**类型:** 信息泄露 (辅助利用)  
**风险:** 中危，可能泄露SSH会话中的部分明文数据  
**投毒风险:** 10%  
**发现时间:** 2025-10-08  
**POC仓库:** [OpenSSH-4.7p1-CVE-2008-5161-Exploit](https://github.com/talha3117/OpenSSH-4.7p1-CVE-2008-5161-Exploit)  

---

### [CVE-2025-10352](CVE-2025-10352-ivansmc00_CVE-2025-10352.md) 🔴 ✅

**名称:** CVE-2025-10352-MelisPlatform-管理员账户创建  
**类型:** 权限提升  
**风险:** 高危，允许未授权用户创建管理员账户  
**投毒风险:** 0%  
**发现时间:** 2025-10-08  
**POC仓库:** [CVE-2025-10352](https://github.com/ivansmc00/CVE-2025-10352)  

---

### [CVE-2025-10351](CVE-2025-10351-ivansmc00_CVE-2025-10351.md) 🔴 ✅

**名称:** CVE-2025-10351-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-10-08  
**POC仓库:** [CVE-2025-10351](https://github.com/ivansmc00/CVE-2025-10351)  

---

### [CVE-2017-7921](CVE-2017-7921-lastvocher_Hikvision-CVE-2017-7921-decryptor.md) 🔴 ✅

**名称:** CVE-2017-7921 - Hikvision IP Camera Authentication Bypass and Config Decryption  
**类型:** 身份验证绕过  
**风险:** 高危，可能导致敏感信息泄露和设备控制  
**投毒风险:** 5%  
**发现时间:** 2025-10-08  
**POC仓库:** [Hikvision-CVE-2017-7921-decryptor](https://github.com/lastvocher/Hikvision-CVE-2017-7921-decryptor)  

---

### [CVE-2025-61183](CVE-2025-61183-thawphone_CVE-2025-61183.md) 🔴 ✅

**名称:** CVE-2025-61183 - VaahCMS Stored XSS  
**类型:** Stored XSS  
**风险:** 高危，攻击者可以控制受害者浏览器执行恶意脚本，可能导致会话劫持、信息窃取、恶意重定向等。  
**投毒风险:** 0%  
**发现时间:** 2025-10-08  
**POC仓库:** [CVE-2025-61183](https://github.com/thawphone/CVE-2025-61183)  

---

### [CVE-2025-54352](CVE-2025-54352-limmmw_CVE-2025-54352.md)  ✅

**名称:** CVE-2025-54352-WordPress-私有文章标题泄露  
**类型:** 信息泄露  
**风险:** 低危，攻击者可以猜测私有和草稿文章的标题  
**投毒风险:** 5%  
**发现时间:** 2025-10-08  
**POC仓库:** [CVE-2025-54352](https://github.com/limmmw/CVE-2025-54352)  

---

### [CVE-2022-0739](CVE-2022-0739-destr4ct_CVE-2022-0739.md) 🔴 ✅

**名称:** CVE-2022-0739-BookingPress-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露、权限提升和远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-10-08  
**POC仓库:** [CVE-2022-0739](https://github.com/destr4ct/CVE-2022-0739)  

---

### [CVE-2022-0739](CVE-2022-0739-Chris01s_CVE-2022-0739.md) 🔴 ✅

**名称:** CVE-2022-0739-BookingPress-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露和管理员权限获取  
**投毒风险:** 0%  
**发现时间:** 2025-10-08  
**POC仓库:** [CVE-2022-0739](https://github.com/Chris01s/CVE-2022-0739)  

---

### [CVE-2022-0739](CVE-2022-0739-BKreisel_CVE-2022-0739.md) 🔴 ✅

**名称:** CVE-2022-0739 - BookingPress WordPress Plugin SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露、未授权访问和远程代码执行（如果数据库用户权限足够高）  
**投毒风险:** 5%  
**发现时间:** 2025-10-08  
**POC仓库:** [CVE-2022-0739](https://github.com/BKreisel/CVE-2022-0739)  

---

### [CVE-2022-0739](CVE-2022-0739-hadrian3689_wp_bookingpress_1.0.11.md) 🔴 ✅

**名称:** CVE-2022-0739-BookingPress-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露，权限提升  
**投毒风险:** 0%  
**发现时间:** 2025-10-08  
**POC仓库:** [wp_bookingpress_1.0.11](https://github.com/hadrian3689/wp_bookingpress_1.0.11)  

---

### [CVE-2022-0739](CVE-2022-0739-G01d3nW01f_CVE-2022-0739.md) 🔴 ✅

**名称:** CVE-2022-0739-BookingPress-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露和权限提升  
**投毒风险:** 0%  
**发现时间:** 2025-10-08  
**POC仓库:** [CVE-2022-0739](https://github.com/G01d3nW01f/CVE-2022-0739)  

---

### [CVE-2022-0739](CVE-2022-0739-viardant_CVE-2022-0739.md) 🔴 

**名称:** CVE-2022-0739-BookingPress-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露和远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-10-08  
**POC仓库:** [CVE-2022-0739](https://github.com/viardant/CVE-2022-0739)  

---

### [CVE-2022-0739](CVE-2022-0739-ElGanz0_CVE-2022-0739.md) 🔴 ✅

**名称:** CVE-2022-0739 - BookingPress - Unauthenticated SQL Injection  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露和服务器控制  
**投毒风险:** 0%  
**发现时间:** 2025-10-08  
**POC仓库:** [CVE-2022-0739](https://github.com/ElGanz0/CVE-2022-0739)  

---

### [CVE-2022-0739](CVE-2022-0739-lhamouche_Bash-exploit-for-CVE-2022-0739.md) 🔴 ✅

**名称:** CVE-2022-0739 - BookingPress < 1.0.11 - Unauthenticated SQL Injection  
**类型:** SQL注入  
**风险:** 高危，未授权的SQL注入可能导致数据泄露、权限提升甚至远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-10-08  
**POC仓库:** [Bash-exploit-for-CVE-2022-0739](https://github.com/lhamouche/Bash-exploit-for-CVE-2022-0739)  

---

### [CVE-2022-0739](CVE-2022-0739-Manjen1218_CVE-2022-0739-Exploitation.md) 🔴 ✅

**名称:** CVE-2022-0739-BookingPress-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露和服务器控制  
**投毒风险:** 0%  
**发现时间:** 2025-10-08  
**POC仓库:** [CVE-2022-0739-Exploitation](https://github.com/Manjen1218/CVE-2022-0739-Exploitation)  

---

### [CVE-2025-29927](CVE-2025-29927-diogolourencodev_middleforce.md) 🔴 ✅

**名称:** CVE-2025-29927-Next.js-中间件授权绕过  
**类型:** 授权绕过  
**风险:** 高危，可能导致未授权访问、数据泄露和权限提升  
**投毒风险:** 10%  
**发现时间:** 2025-10-08  
**POC仓库:** [middleforce](https://github.com/diogolourencodev/middleforce)  

---

### [CVE-2025-29927](CVE-2025-29927-Bongni_CVE-2025-29927.md) 🔴 ✅

**名称:** CVE-2025-29927-Next.js-权限绕过  
**类型:** 权限绕过  
**风险:** 高危，可能导致未经授权的访问和数据泄露  
**投毒风险:** 5%  
**发现时间:** 2025-10-08  
**POC仓库:** [CVE-2025-29927](https://github.com/Bongni/CVE-2025-29927)  

---

### [CVE-2025-7401](CVE-2025-7401-Nxploited_CVE-2025-7401.md) 🔴 ✅

**名称:** CVE-2025-7401-Premium Age Verification / Restriction for WordPress-Unauthenticated Arbitrary File Read and Write  
**类型:** 任意文件读取/写入  
**风险:** 高危，可能导致敏感信息泄露和远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-10-07  
**POC仓库:** [CVE-2025-7401](https://github.com/Nxploited/CVE-2025-7401)  

---

### [CVE-2025-44823](CVE-2025-44823-skraft9_CVE-2025-44823.md) 🔴 ✅

**名称:** CVE-2025-44823-Nagios Log Server-API密钥泄露  
**类型:** API密钥泄露  
**风险:** 高危，可能导致权限提升和系统完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-10-07  
**POC仓库:** [CVE-2025-44823](https://github.com/skraft9/CVE-2025-44823)  

---

### [CVE-2025-52021](CVE-2025-52021-hafizgemilang_CVE-2025-52021.md) 🔴 

**名称:** CVE-2025-52021 - Online Shopping System Advanced - Time-Based Blind SQL Injection  
**类型:** Time-Based Blind SQL Injection  
**风险:** 高危，可能导致数据泄露  
**投毒风险:** 10%  
**发现时间:** 2025-10-07  
**POC仓库:** [CVE-2025-52021](https://github.com/hafizgemilang/CVE-2025-52021)  

---

### [CVE-2025-56243](CVE-2025-56243-hafizgemilang_CVE-2025-56243.md) 🟡 

**名称:** CVE-2025-56243 - Event Management System (v1.0) Reflected XSS  
**类型:** Reflected XSS  
**风险:** 中危，可能导致会话劫持、钓鱼攻击或恶意重定向  
**投毒风险:** 10%  
**发现时间:** 2025-10-07  
**POC仓库:** [CVE-2025-56243](https://github.com/hafizgemilang/CVE-2025-56243)  

---

### [CVE-2025-7441](CVE-2025-7441-Nxploited_CVE-2025-7441.md) 🔴 ✅

**名称:** CVE-2025-7441 - StoryChief WordPress Plugin Unauthenticated Arbitrary File Upload  
**类型:** Arbitrary File Upload  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-10-07  
**POC仓库:** [CVE-2025-7441](https://github.com/Nxploited/CVE-2025-7441)  

---

### [CVE-2025-61882](CVE-2025-61882-B1ack4sh_Blackash-CVE-2025-61882.md)  

**名称:** CVE-2025-61882 - Oracle Concurrent Processing BI Publisher Integration takeover  
**类型:** 未授权远程命令执行  
**风险:** 严重，可导致完全接管Oracle Concurrent Processing  
**投毒风险:** 99%  
**发现时间:** 2025-10-07  
**POC仓库:** [Blackash-CVE-2025-61882](https://github.com/B1ack4sh/Blackash-CVE-2025-61882)  

---

### [CVE-2025-49844](CVE-2025-49844-lastvocher_redis-CVE-2025-49844.md) 🔴 ✅

**名称:** CVE-2025-49844-Redis-Lua Use-After-Free  
**类型:** Use-After-Free  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-10-07  
**POC仓库:** [redis-CVE-2025-49844](https://github.com/lastvocher/redis-CVE-2025-49844)  

---

### [CVE-2021-41773](CVE-2021-41773-MuhammadHuzaifaAsif_security-lab.md) 🔴 ✅

**名称:** CVE-2021-41773-Apache HTTP Server Path Traversal  
**类型:** 路径遍历/远程代码执行  
**风险:** 高危，可能导致文件泄露和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-10-07  
**POC仓库:** [security-lab](https://github.com/MuhammadHuzaifaAsif/security-lab)  

---

### [CVE-2021-41773](CVE-2021-41773-gunzf0x_CVE-2021-41773.md) 🔴 ✅

**名称:** CVE-2021-41773-Apache HTTP Server-路径遍历和RCE  
**类型:** 路径遍历和远程代码执行  
**风险:** 高危，可能导致敏感信息泄露和远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-10-07  
**POC仓库:** [CVE-2021-41773](https://github.com/gunzf0x/CVE-2021-41773)  

---

### [CVE-2025-61984](CVE-2025-61984-dgl_cve-2025-61984-poc.md) 🟡 ✅

**名称:** CVE-2025-61984 - OpenSSH 用户名控制字符注入导致代码执行  
**类型:** 代码注入  
**风险:** 中危，可能导致远程代码执行，影响系统完整性  
**投毒风险:** 20%  
**发现时间:** 2025-10-07  
**POC仓库:** [cve-2025-61984-poc](https://github.com/dgl/cve-2025-61984-poc)  

---

### [CVE-2025-46818](CVE-2025-46818-dwisiswant0_CVE-2025-46818.md) 🟡 ✅

**名称:** CVE-2025-46818 - Redis Lua 沙箱跨用户逃逸  
**类型:** 权限提升/代码注入  
**风险:** 中危，Authenticated users can execute LUA scripts as a different user  
**投毒风险:** 0%  
**发现时间:** 2025-10-07  
**POC仓库:** [CVE-2025-46818](https://github.com/dwisiswant0/CVE-2025-46818)  

---

### [CVE-2025-46819](CVE-2025-46819-dwisiswant0_CVE-2025-46819.md) 🟡 ✅

**名称:** CVE-2025-46819-Redis-DoS  
**类型:** 拒绝服务 (DoS)  
**风险:** 中危，可能导致服务中断  
**投毒风险:** 0%  
**发现时间:** 2025-10-07  
**POC仓库:** [CVE-2025-46819](https://github.com/dwisiswant0/CVE-2025-46819)  

---

### [CVE-2025-46817](CVE-2025-46817-dwisiswant0_CVE-2025-46817.md) 🔴 ✅

**名称:** CVE-2025-46817-Redis-Lua整数溢出  
**类型:** 整数溢出  
**风险:** 高危，可能导致拒绝服务或远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-10-07  
**POC仓库:** [CVE-2025-46817](https://github.com/dwisiswant0/CVE-2025-46817)  

---

### [CVE-2025-49844](CVE-2025-49844-dwisiswant0_CVE-2025-49844.md) 🔴 ✅

**名称:** CVE-2025-49844 - Redis Lua Use-After-Free  
**类型:** Use-After-Free  
**风险:** 高危，远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-10-07  
**POC仓库:** [CVE-2025-49844](https://github.com/dwisiswant0/CVE-2025-49844)  

---

### [CVE-2025-59934](CVE-2025-59934-suriryuk_cve-2025-59934.md)  ✅

**名称:** CVE-2025-59934-Formbricks-JWT签名绕过  
**类型:** JWT签名绕过  
**风险:** 严重，可能导致账户接管  
**投毒风险:** 5%  
**发现时间:** 2025-10-07  
**POC仓库:** [cve-2025-59934](https://github.com/suriryuk/cve-2025-59934)  

---

### [CVE-2025-49844](CVE-2025-49844-gopinaath_CVE-2025-49844-discovery.md) 🔴 ✅

**名称:** CVE-2025-49844-Redis-Lua Use-After-Free  
**类型:** Use-After-Free  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-10-07  
**POC仓库:** [CVE-2025-49844-discovery](https://github.com/gopinaath/CVE-2025-49844-discovery)  

---

### [CVE-2025-32463](CVE-2025-32463-r3dBust3r_CVE-2025-32463.md) 🔴 ✅

**名称:** CVE-2025-32463-Sudo-本地提权  
**类型:** 本地提权  
**风险:** 高危，本地用户可以获取root权限  
**投毒风险:** 5%  
**发现时间:** 2025-10-07  
**POC仓库:** [CVE-2025-32463](https://github.com/r3dBust3r/CVE-2025-32463)  

---

### [CVE-2025-61882](CVE-2025-61882-watchtowrlabs_watchTowr-vs-Oracle-E-Business-Suite-CVE-2025-61882.md) 🔴 ✅

**名称:** CVE-2025-61882 - Oracle Concurrent Processing Pre-Auth RCE  
**类型:** 远程代码执行  
**风险:** 高危，可完全控制系统  
**投毒风险:** 0%  
**发现时间:** 2025-10-06  
**POC仓库:** [watchTowr-vs-Oracle-E-Business-Suite-CVE-2025-61882](https://github.com/watchtowrlabs/watchTowr-vs-Oracle-E-Business-Suite-CVE-2025-61882)  

---

### [CVE-2025-61882](CVE-2025-61882-Sachinart_CVE-2025-61882.md) 🔴 ✅

**名称:** CVE-2025-61882 - Oracle E-Business Suite RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可导致服务器完全控制  
**投毒风险:** 20%  
**发现时间:** 2025-10-06  
**POC仓库:** [CVE-2025-61882](https://github.com/Sachinart/CVE-2025-61882)  

---

### [CVE-2023-45612](CVE-2023-45612-bbugdigger_ktor-xxe-poc.md) 🔴 ✅

**名称:** CVE-2023-45612-Ktor-XXE  
**类型:** XXE  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-10-06  
**POC仓库:** [ktor-xxe-poc](https://github.com/bbugdigger/ktor-xxe-poc)  

---

### [CVE-2023-45612](CVE-2023-45612-infernosalex_CVE-2023-45612-PoC.md) 🔴 ✅

**名称:** CVE-2023-45612 - JetBrains Ktor XXE  
**类型:** XML外部实体注入 (XXE)  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-10-06  
**POC仓库:** [CVE-2023-45612-PoC](https://github.com/infernosalex/CVE-2023-45612-PoC)  

---

### [CVE-2025-50505](CVE-2025-50505-bron1e_CVE-2025-50505.md) 🔴 ✅

**名称:** CVE-2025-50505 - Clash Verge Rev 未授权API导致任意命令执行和权限提升  
**类型:** 命令注入  
**风险:** 高危，可导致本地提权和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-10-06  
**POC仓库:** [CVE-2025-50505](https://github.com/bron1e/CVE-2025-50505)  

---

### [CVE-2025-8625](CVE-2025-8625-ret0x2A_CVE-2025-8625.md) 🔴 ✅

**名称:** CVE-2025-8625 - Copypress Rest API 未授权远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，未授权远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-10-06  
**POC仓库:** [CVE-2025-8625](https://github.com/ret0x2A/CVE-2025-8625)  

---

### [CVE-2024-23897](CVE-2024-23897-amalpvatayam67_day03-jenkins-23897.md) 🔴 ✅

**名称:** CVE-2024-23897-Jenkins-任意文件读取  
**类型:** 任意文件读取  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-10-06  
**POC仓库:** [day03-jenkins-23897](https://github.com/amalpvatayam67/day03-jenkins-23897)  

---

### [CVE-2024-23897](CVE-2024-23897-hybinn_CVE-2024-23897.md) 🔴 ✅

**名称:** CVE-2024-23897-Jenkins-任意文件读取  
**类型:** 任意文件读取  
**风险:** 高危，可能导致敏感信息泄露，进而可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-10-06  
**POC仓库:** [CVE-2024-23897](https://github.com/hybinn/CVE-2024-23897)  

---

### [CVE-2025-9074](CVE-2025-9074-OilSeller2001_PoC-for-CVE-2025-9074.md) 🔴 ✅

**名称:** CVE-2025-9074 - Docker API 未授权访问  
**类型:** 未授权访问  
**风险:** 高危，可导致主机文件系统完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-10-06  
**POC仓库:** [PoC-for-CVE-2025-9074](https://github.com/OilSeller2001/PoC-for-CVE-2025-9074)  

---

### [CVE-2024-38820](CVE-2024-38820-kadamnayan_POC-CVE-2024-38820.md)  ✅

**名称:** CVE-2024-38820 - Spring Framework DataBinder Locale Bypass  
**类型:** 数据绑定绕过  
**风险:** 低危，可能导致数据篡改  
**投毒风险:** 0%  
**发现时间:** 2025-10-06  
**POC仓库:** [POC-CVE-2024-38820](https://github.com/kadamnayan/POC-CVE-2024-38820)  

---

### [CVE-2025-8061](CVE-2025-8061-symeonp_Lenovo-CVE-2025-8061.md) 🔴 ✅

**名称:** CVE-2025-8061-Lenovo Dispatcher Driver-权限提升  
**类型:** 权限提升  
**风险:** 高危，允许本地用户以提升的权限执行代码  
**投毒风险:** 10%  
**发现时间:** 2025-10-06  
**POC仓库:** [Lenovo-CVE-2025-8061](https://github.com/symeonp/Lenovo-CVE-2025-8061)  

---

### [CVE-2025-51586](CVE-2025-51586-7h30th3r0n3_CVE-2025-51586-PrestaShop-PoC.md)  ✅

**名称:** CVE-2025-51586 - PrestaShop AdminLogin Email Enumeration  
**类型:** 信息泄露  
**风险:** 低危，泄露管理员邮箱  
**投毒风险:** 0%  
**发现时间:** 2025-10-06  
**POC仓库:** [CVE-2025-51586-PrestaShop-PoC](https://github.com/7h30th3r0n3/CVE-2025-51586-PrestaShop-PoC)  

---

### [CVE-2025-61882](CVE-2025-61882-allinsthon_CVE-2025-61882.md)  ✅

**名称:** CVE-2025-61882 - Oracle E-Business Suite RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 严重，可能导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-10-06  
**POC仓库:** [CVE-2025-61882](https://github.com/allinsthon/CVE-2025-61882)  

---

### [CVE-2024-30088](CVE-2024-30088-Justintroup85_exploits-forsale-collateral-damage.md) 🔴 

**名称:** CVE-2024-30088 Windows Kernel Elevation of Privilege Vulnerability  
**类型:** 特权提升  
**风险:** 高危，本地攻击者可利用该漏洞获取SYSTEM权限  
**投毒风险:** 80%  
**发现时间:** 2025-10-06  
**POC仓库:** [exploits-forsale-collateral-damage](https://github.com/Justintroup85/exploits-forsale-collateral-damage)  

---

### [CVE-2024-30088](CVE-2024-30088-NextGenPentesters_CVE-2024-30088-.md) 🔴 ✅

**名称:** CVE-2024-30088-Windows Kernel Elevation of Privilege Vulnerability  
**类型:** 权限提升  
**风险:** 高危，本地权限提升至SYSTEM  
**投毒风险:** 10%  
**发现时间:** 2025-10-06  
**POC仓库:** [CVE-2024-30088-](https://github.com/NextGenPentesters/CVE-2024-30088-)  

---

### [CVE-2024-30088](CVE-2024-30088-Zombie-Kaiser_CVE-2024-30088-Windows-poc.md) 🔴 ✅

**名称:** CVE-2024-30088 Windows Kernel Elevation of Privilege Vulnerability  
**类型:** 权限提升  
**风险:** 高危，允许本地攻击者获取 SYSTEM 权限  
**投毒风险:** 0%  
**发现时间:** 2025-10-06  
**POC仓库:** [CVE-2024-30088-Windows-poc](https://github.com/Zombie-Kaiser/CVE-2024-30088-Windows-poc)  

---

### [CVE-2024-30088](CVE-2024-30088-Admin9961_CVE-2024-30088.md) 🔴 ✅

**名称:** CVE-2024-30088 Windows Kernel 提权漏洞  
**类型:** 权限提升  
**风险:** 高危，可能导致本地权限提升  
**投毒风险:** 0%  
**发现时间:** 2025-10-06  
**POC仓库:** [CVE-2024-30088](https://github.com/Admin9961/CVE-2024-30088)  

---

### [CVE-2024-30088](CVE-2024-30088-tykawaii98_CVE-2024-30088.md) 🔴 ✅

**名称:** CVE-2024-30088 Windows Kernel Elevation of Privilege Vulnerability  
**类型:** 权限提升  
**风险:** 高危，可导致系统权限提升  
**投毒风险:** 10%  
**发现时间:** 2025-10-06  
**POC仓库:** [CVE-2024-30088](https://github.com/tykawaii98/CVE-2024-30088)  

---

### [CVE-2024-30088](CVE-2024-30088-exploits-forsale_collateral-damage.md) 🔴 ✅

**名称:** CVE-2024-30088 Windows Kernel 权限提升漏洞  
**类型:** TOCTOU 竞争条件  
**风险:** 高危，可能导致权限提升至 SYSTEM  
**投毒风险:** 10%  
**发现时间:** 2025-10-06  
**POC仓库:** [collateral-damage](https://github.com/exploits-forsale/collateral-damage)  

---

### [CVE-2025-53770](CVE-2025-53770-bitsalv_ToolShell-Honeypot.md) 🔴 ✅

**名称:** CVE-2025-53770 Microsoft SharePoint Server 远程代码执行漏洞  
**类型:** 反序列化漏洞  
**风险:** 高危，远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-10-06  
**POC仓库:** [ToolShell-Honeypot](https://github.com/bitsalv/ToolShell-Honeypot)  

---

### [CVE-2025-59489](CVE-2025-59489-RealtekDotSys_Meteor.md) 🔴 ✅

**名称:** CVE-2025-59489-Unity Runtime-参数注入导致代码执行  
**类型:** 参数注入/代码执行  
**风险:** 高危，可能导致远程代码执行和信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-10-06  
**POC仓库:** [Meteor](https://github.com/RealtekDotSys/Meteor)  

---

### [CVE-2025-59489](CVE-2025-59489-GithubKillsMyOpsec_CVE-2025-59489-POC.md) 🔴 ✅

**名称:** CVE-2025-59489-Unity Runtime参数注入  
**类型:** 参数注入  
**风险:** 高危，可能导致任意代码执行和信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-10-06  
**POC仓库:** [CVE-2025-59489-POC](https://github.com/GithubKillsMyOpsec/CVE-2025-59489-POC)  

---

### [CVE-2025-41244](CVE-2025-41244-haspiranti_CVE-2025-41244-PoC.md) 🔴 ✅

**名称:** CVE-2025-41244 - VMware Aria Operations/Tools 本地提权  
**类型:** 本地权限提升  
**风险:** 高危，可获得 root 权限  
**投毒风险:** 0%  
**发现时间:** 2025-10-06  
**POC仓库:** [CVE-2025-41244-PoC](https://github.com/haspiranti/CVE-2025-41244-PoC)  

---

### [CVE-2018-16763](CVE-2018-16763-Cyberuser-hash_CVE-2018-16763.md) 🔴 ✅

**名称:** CVE-2018-16763-FUEL CMS-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-10-05  
**POC仓库:** [CVE-2018-16763](https://github.com/Cyberuser-hash/CVE-2018-16763)  

---

### [CVE-2025-61882](CVE-2025-61882-rxerium_CVE-2025-61882.md) 🔴 ✅

**名称:** CVE-2025-61882-Oracle Concurrent Processing-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-10-05  
**POC仓库:** [CVE-2025-61882](https://github.com/rxerium/CVE-2025-61882)  

---

### [CVE-2025-55616](CVE-2025-55616-livepwn_CVE-2025-55616.md) 🔴 ✅

**名称:** CVE-2025-55616-Zsh-RCE  
**类型:** RCE  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 20%  
**发现时间:** 2025-10-05  
**POC仓库:** [CVE-2025-55616](https://github.com/livepwn/CVE-2025-55616)  

---

### [CVE-2021-44228](CVE-2021-44228-b-abderrahmane_CVE-2021-44228-playground.md) 🔴 ✅

**名称:** CVE-2021-44228-Apache Log4j2-JNDI注入  
**类型:** JNDI注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-10-05  
**POC仓库:** [CVE-2021-44228-playground](https://github.com/b-abderrahmane/CVE-2021-44228-playground)  

---

### [CVE-2021-44228](CVE-2021-44228-moften_Log4Shell.md) 🔴 ✅

**名称:** CVE-2021-44228 - Apache Log4j2 Log4Shell JNDI注入  
**类型:** 远程代码执行  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-10-05  
**POC仓库:** [Log4Shell](https://github.com/moften/Log4Shell)  

---

### [CVE-2021-44228](CVE-2021-44228-KamalideenAK_Microsoft-Defender-for-Endpoint-Deployment-on-Windows-10-11-device.md) 🔴 ✅

**名称:** CVE-2021-44228 Apache Log4j2 远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-10-05  
**POC仓库:** [Microsoft-Defender-for-Endpoint-Deployment-on-Windows-10-11-device](https://github.com/KamalideenAK/Microsoft-Defender-for-Endpoint-Deployment-on-Windows-10-11-device)  

---

### [CVE-2021-44228](CVE-2021-44228-arabindadora_log4shell.md)  ✅

**名称:** CVE-2021-44228 Log4Shell RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 严重，允许未经身份验证的远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-10-05  
**POC仓库:** [log4shell](https://github.com/arabindadora/log4shell)  

---

### [CVE-2021-44228](CVE-2021-44228-d4ngkh04w_CVE-2021-44228-Apache-Log4j.md) 🔴 ✅

**名称:** CVE-2021-44228-Log4Shell-RCE  
**类型:** 远程代码执行(RCE)  
**风险:** 极高危，可能导致完全控制受影响的系统  
**投毒风险:** 0%  
**发现时间:** 2025-10-05  
**POC仓库:** [CVE-2021-44228-Apache-Log4j](https://github.com/d4ngkh04w/CVE-2021-44228-Apache-Log4j)  

---

### [CVE-2025-53770](CVE-2025-53770-victormbogu1_LetsDefend-SOC342-CVE-2025-53770-SharePoint-ToolShell-Auth-Bypass-andRCE-EventID-320.md) 🔴 ✅

**名称:** CVE-2025-53770-Microsoft SharePoint Server 远程代码执行漏洞  
**类型:** 反序列化漏洞  
**风险:** 高危，允许未经授权的攻击者通过网络执行代码  
**投毒风险:** 10%  
**发现时间:** 2025-10-05  
**POC仓库:** [LetsDefend-SOC342-CVE-2025-53770-SharePoint-ToolShell-Auth-Bypass-andRCE-EventID-320](https://github.com/victormbogu1/LetsDefend-SOC342-CVE-2025-53770-SharePoint-ToolShell-Auth-Bypass-andRCE-EventID-320)  

---

### [CVE-2025-52970](CVE-2025-52970-imbas007_POC-CVE-2025-52970.md) 🔴 ✅

**名称:** CVE-2025-52970-FortiWeb-身份验证绕过和远程代码执行  
**类型:** 身份验证绕过和远程代码执行  
**风险:** 高危，允许未经身份验证的远程攻击者获得管理员权限并在设备上执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-10-05  
**POC仓库:** [POC-CVE-2025-52970](https://github.com/imbas007/POC-CVE-2025-52970)  

---

### [CVE-2025-6934](CVE-2025-6934-Jenderal92_WP-CVE-2025-6934.md) 🔴 ✅

**名称:** CVE-2025-6934-Opal Estate Pro-权限提升  
**类型:** 权限提升  
**风险:** 高危，可导致管理员权限被恶意用户获取，进而控制整个WordPress站点。  
**投毒风险:** 0%  
**发现时间:** 2025-10-05  
**POC仓库:** [WP-CVE-2025-6934](https://github.com/Jenderal92/WP-CVE-2025-6934)  

---

### [CVE-2025-6554](CVE-2025-6554-mistymntncop_CVE-2025-6554.md) 🔴 ✅

**名称:** CVE-2025-6554 - Google Chrome V8 Type Confusion  
**类型:** Type Confusion  
**风险:** 高危，允许远程攻击者通过精心设计的HTML页面执行任意读/写操作  
**投毒风险:** 10%  
**发现时间:** 2025-10-05  
**POC仓库:** [CVE-2025-6554](https://github.com/mistymntncop/CVE-2025-6554)  

---

### [CVE-2025-1338](CVE-2025-1338-jxcaxtc_CVE-2025-1338.md) 🔴 ✅

**名称:** CVE-2025-1338-NUUO Camera-命令注入  
**类型:** 命令注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-10-05  
**POC仓库:** [CVE-2025-1338](https://github.com/jxcaxtc/CVE-2025-1338)  

---

### [CVE-2025-57819](CVE-2025-57819-JakovBis_CVE-2025-57819_FreePBX-PoC.md) 🔴 ✅

**名称:** CVE-2025-57819 FreePBX Authentication Bypass SQL Injection RCE  
**类型:** Authentication Bypass, SQL Injection, Remote Code Execution  
**风险:** Critical，未经身份验证的攻击者可以控制 FreePBX 服务器  
**投毒风险:** 85%  
**发现时间:** 2025-10-04  
**POC仓库:** [CVE-2025-57819_FreePBX-PoC](https://github.com/JakovBis/CVE-2025-57819_FreePBX-PoC)  

---

### [CVE-2020-1472](CVE-2020-1472-100HnoMeuNome_ZeroLogon-CVE-2020-1472-lab.md) 🔴 ✅

**名称:** CVE-2020-1472 Zerologon  
**类型:** 权限提升  
**风险:** 高危，可能导致域管理员权限提升  
**投毒风险:** 10%  
**发现时间:** 2025-10-04  
**POC仓库:** [ZeroLogon-CVE-2020-1472-lab](https://github.com/100HnoMeuNome/ZeroLogon-CVE-2020-1472-lab)  

---

### [CVE-2017-5618](CVE-2017-5618-RXDarkee_CVE-2017-5618-Screen-4.5.0-Root.md) 🔴 ✅

**名称:** CVE-2017-5618-GNU screen-权限提升  
**类型:** 权限提升  
**风险:** 高危，可能导致本地用户获取 root 权限  
**投毒风险:** 10%  
**发现时间:** 2025-10-04  
**POC仓库:** [CVE-2017-5618-Screen-4.5.0-Root](https://github.com/RXDarkee/CVE-2017-5618-Screen-4.5.0-Root)  

---

### [CVE-2025-39946](CVE-2025-39946-farazsth98_exploit-CVE-2025-39946.md) 🔴 ✅

**名称:** CVE-2025-39946-Linux Kernel TLS堆溢出  
**类型:** 堆溢出  
**风险:** 高危，可能导致内核崩溃或任意代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-10-04  
**POC仓库:** [exploit-CVE-2025-39946](https://github.com/farazsth98/exploit-CVE-2025-39946)  

---

### [CVE-2024-7627](CVE-2024-7627-siunam321_CVE-2024-7627-PoC.md) 🔴 ✅

**名称:** CVE-2024-7627-Bit File Manager-远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可完全控制服务器  
**投毒风险:** 5%  
**发现时间:** 2025-10-04  
**POC仓库:** [CVE-2024-7627-PoC](https://github.com/siunam321/CVE-2024-7627-PoC)  

---

### [CVE-2024-7627](CVE-2024-7627-lkmn1_CVE-2024-7627.md) 🔴 ✅

**名称:** CVE-2024-7627 - Bit File Manager WordPress Plugin RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，允许未经身份验证的攻击者执行任意代码  
**投毒风险:** 1%  
**发现时间:** 2025-10-04  
**POC仓库:** [CVE-2024-7627](https://github.com/lkmn1/CVE-2024-7627)  

---

### [CVE-2025-10184](CVE-2025-10184-Webpage-gh_CVE-2025-10184-PoC.md) 🔴 ✅

**名称:** CVE-2025-10184-OnePlus OxygenOS-Telephony provider权限绕过与SQL注入  
**类型:** 权限绕过, SQL注入  
**风险:** 高危，可导致SMS/MMS数据泄露，破坏SMS-based MFA  
**投毒风险:** 10%  
**发现时间:** 2025-10-04  
**POC仓库:** [CVE-2025-10184-PoC](https://github.com/Webpage-gh/CVE-2025-10184-PoC)  

---

### [CVE-2024-36401](CVE-2024-36401-funnyDog896_CVE-2024-36401-WoodpeckerPlugin.md) 🔴 ✅

**名称:** CVE-2024-36401-GeoServer-RCE  
**类型:** 远程代码执行  
**风险:** 高危，未授权的攻击者可以通过构造恶意请求执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-10-04  
**POC仓库:** [CVE-2024-36401-WoodpeckerPlugin](https://github.com/funnyDog896/CVE-2024-36401-WoodpeckerPlugin)  

---

### [CVE-2024-36401](CVE-2024-36401-URJACK2025_CVE-2024-36401.md) 🔴 ✅

**名称:** CVE-2024-36401 GeoServer 远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，未经身份验证的远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-10-04  
**POC仓库:** [CVE-2024-36401](https://github.com/URJACK2025/CVE-2024-36401)  

---

### [CVE-2025-30208](CVE-2025-30208-gonn4cry_CVE-2025-30208.md) 🟡 ✅

**名称:** CVE-2025-30208-Vite-任意文件读取  
**类型:** 任意文件读取  
**风险:** 中危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-10-04  
**POC仓库:** [CVE-2025-30208](https://github.com/gonn4cry/CVE-2025-30208)  

---

### [CVE-2025-8625](CVE-2025-8625-Nxploited_CVE-2025-8625.md)  ✅

**名称:** CVE-2025-8625-Copypress Rest API-RCE  
**类型:** 远程代码执行  
**风险:** 严重，可能导致服务器完全控制  
**投毒风险:** 5%  
**发现时间:** 2025-10-03  
**POC仓库:** [CVE-2025-8625](https://github.com/Nxploited/CVE-2025-8625)  

---

### [CVE-2025-60736](CVE-2025-60736-WinDyAlphA_CVE-2025-60736.md) 🔴 ✅

**名称:** CVE-2025-60736-Online Medicine Guide-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露、未授权访问数据库、远程代码执行（如果数据库用户权限足够高）  
**投毒风险:** 10%  
**发现时间:** 2025-10-03  
**POC仓库:** [CVE-2025-60736](https://github.com/WinDyAlphA/CVE-2025-60736)  

---

### [CVE-2025-34226](CVE-2025-34226-Eyodav_CVE-2025-34226.md) 🔴 ✅

**名称:** CVE-2025-34226 - OpenPLC Runtime Persistent DoS  
**类型:** 持久性拒绝服务 (DoS)  
**风险:** 高危，导致OpenPLC Runtime无法启动，需要重装  
**投毒风险:** 0%  
**发现时间:** 2025-10-03  
**POC仓库:** [CVE-2025-34226](https://github.com/Eyodav/CVE-2025-34226)  

---

### [CVE-2025-7771](CVE-2025-7771-fxrstor_ThrottleStopPoC.md) 🔴 ✅

**名称:** CVE-2025-7771-ThrottleStop-权限提升  
**类型:** 权限提升  
**风险:** 高危，允许本地攻击者以内核权限执行任意代码，可能导致系统完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-10-03  
**POC仓库:** [ThrottleStopPoC](https://github.com/fxrstor/ThrottleStopPoC)  

---

### [CVE-2025-7771](CVE-2025-7771-Demoo1337_ThrottleStop.md) 🔴 ✅

**名称:** CVE-2025-7771 – ThrottleStop.sys Privilege Escalation  
**类型:** 权限提升  
**风险:** 高危，允许本地攻击者在内核上下文中执行任意代码，导致权限提升和潜在的后续攻击，例如禁用安全软件或绕过内核级保护。  
**投毒风险:** 10%  
**发现时间:** 2025-10-03  
**POC仓库:** [ThrottleStop](https://github.com/Demoo1337/ThrottleStop)  

---

### [CVE-2025-7771](CVE-2025-7771-Gabriel-Lacorte_CVE-2025-7771.md) 🔴 ✅

**名称:** CVE-2025-7771-ThrottleStop-权限提升/代码执行  
**类型:** 权限提升/代码执行  
**风险:** 高危，允许本地攻击者在内核上下文中执行任意代码，导致权限提升和潜在的后续攻击，例如禁用安全软件或绕过内核级保护。  
**投毒风险:** 10%  
**发现时间:** 2025-10-03  
**POC仓库:** [CVE-2025-7771](https://github.com/Gabriel-Lacorte/CVE-2025-7771)  

---

### [CVE-2025-60787](CVE-2025-60787-prabhatverma47_CVE-2025-60787.md) 🔴 ✅

**名称:** CVE-2025-60787-motionEye-OS命令注入  
**类型:** OS命令注入  
**风险:** 高危，远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-10-03  
**POC仓库:** [CVE-2025-60787](https://github.com/prabhatverma47/CVE-2025-60787)  

---

### [CVE-2025-7558](CVE-2025-7558-rundas-r00t_CVE-2025-7558-PoC.md) 🔴 ✅

**名称:** CVE-2025-7558-code-projects Voting System-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露、数据篡改和权限提升  
**投毒风险:** 10%  
**发现时间:** 2025-10-03  
**POC仓库:** [CVE-2025-7558-PoC](https://github.com/rundas-r00t/CVE-2025-7558-PoC)  

---

### [CVE-2025-61622](CVE-2025-61622-fa1consec_cve_2025_61622_poc.md) 🔴 ✅

**名称:** CVE-2025-61622-Apache Fory/Fury-反序列化RCE  
**类型:** 反序列化远程代码执行  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-10-03  
**POC仓库:** [cve_2025_61622_poc](https://github.com/fa1consec/cve_2025_61622_poc)  

---

### [CVE-2025-9286](CVE-2025-9286-Nxploited_CVE-2025-9286.md) 🔴 ✅

**名称:** CVE-2025-9286 - Appy Pie Connect for WooCommerce 未授权特权提升  
**类型:** 权限提升  
**风险:** 高危，未授权攻击者可重置任意用户密码，包括管理员，从而获取管理权限。  
**投毒风险:** 1%  
**发现时间:** 2025-10-03  
**POC仓库:** [CVE-2025-9286](https://github.com/Nxploited/CVE-2025-9286)  

---

### [CVE-2025-24893](CVE-2025-24893-ibrahmsql_CVE-2025-24893.md)  ✅

**名称:** CVE-2025-24893 - XWiki SolrSearch SSTI RCE  
**类型:** 服务器端模板注入（SSTI） -> 远程代码执行（RCE）  
**风险:** 严重，未经身份验证的远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-10-02  
**POC仓库:** [CVE-2025-24893](https://github.com/ibrahmsql/CVE-2025-24893)  

---

### [CVE-2025-24893](CVE-2025-24893-gotr00t0day_CVE-2025-24893.md) 🔴 ✅

**名称:** CVE-2025-24893-XWiki-SSTI  
**类型:** 服务器端模板注入 (SSTI)  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-10-02  
**POC仓库:** [CVE-2025-24893](https://github.com/gotr00t0day/CVE-2025-24893)  

---

### [CVE-2025-55972](CVE-2025-55972-Szym0n13k_CVE-2025-55972-Remote-Unauthenticated-Denial-of-Service-DoS-in-TCL-Smart-TV-UPnP-DLNA-AVTransport.md) 🔴 ✅

**名称:** CVE-2025-55972 - TCL Smart TV UPnP/DLNA AVTransport 远程未授权拒绝服务漏洞  
**类型:** 拒绝服务 (DoS)  
**风险:** 高危，可能导致设备无响应  
**投毒风险:** 0%  
**发现时间:** 2025-10-02  
**POC仓库:** [CVE-2025-55972-Remote-Unauthenticated-Denial-of-Service-DoS-in-TCL-Smart-TV-UPnP-DLNA-AVTransport](https://github.com/Szym0n13k/CVE-2025-55972-Remote-Unauthenticated-Denial-of-Service-DoS-in-TCL-Smart-TV-UPnP-DLNA-AVTransport)  

---

### [CVE-2025-55971](CVE-2025-55971-Szym0n13k_CVE-2025-55971-Blind-Unauthenticated-SSRF-in-TCL-Smart-TV-UPnP-DLNA-AVTransport.md) 🟡 ✅

**名称:** CVE-2025-55971-TCL Smart TV UPnP SSRF  
**类型:** Server-Side Request Forgery (SSRF)  
**风险:** 中危，可导致设备对外发起请求，可能被利用于探测内网或攻击其他服务。  
**投毒风险:** 10%  
**发现时间:** 2025-10-02  
**POC仓库:** [CVE-2025-55971-Blind-Unauthenticated-SSRF-in-TCL-Smart-TV-UPnP-DLNA-AVTransport](https://github.com/Szym0n13k/CVE-2025-55971-Blind-Unauthenticated-SSRF-in-TCL-Smart-TV-UPnP-DLNA-AVTransport)  

---

### [CVE-2025-31161](CVE-2025-31161-0xDTC_CrushFTP-auth-bypass-CVE-2025-31161.md) 🔴 ✅

**名称:** CVE-2025-31161-CrushFTP身份认证绕过  
**类型:** 身份认证绕过  
**风险:** 高危，可能导致完全系统控制  
**投毒风险:** 5%  
**发现时间:** 2025-10-02  
**POC仓库:** [CrushFTP-auth-bypass-CVE-2025-31161](https://github.com/0xDTC/CrushFTP-auth-bypass-CVE-2025-31161)  

---

### [CVE-2025-57457](CVE-2025-57457-restdone_CVE-2025-57457.md) 🔴 ✅

**名称:** CURO UC300 IP Phone OS Command Injection  
**类型:** OS Command Injection  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-10-02  
**POC仓库:** [CVE-2025-57457](https://github.com/restdone/CVE-2025-57457)  

---

### [CVE-2025-8359](CVE-2025-8359-Nxploited_CVE-2025-8359.md) 🔴 ✅

**名称:** CVE-2025-8359-AdForest-身份验证绕过  
**类型:** 身份验证绕过  
**风险:** 高危，可能导致任意用户登录，包括管理员  
**投毒风险:** 10%  
**发现时间:** 2025-10-02  
**POC仓库:** [CVE-2025-8359](https://github.com/Nxploited/CVE-2025-8359)  

---

### [CVE-2025-56381](CVE-2025-56381-MoAlali_CVE-2025-56381.md) 🔴 ✅

**名称:** CVE-2025-56381 - ERPNext/Frappe Authenticated SQL Injection  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露、数据库枚举、权限提升、任意SQL代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-10-01  
**POC仓库:** [CVE-2025-56381](https://github.com/MoAlali/CVE-2025-56381)  

---

### [CVE-2025-56380](CVE-2025-56380-MoAlali_CVE-2025-56380.md) 🔴 ✅

**名称:** CVE-2025-56380 - Frappe/ERPNext 时间型盲注  
**类型:** SQL注入 (时间盲注)  
**风险:** 高危，可能导致数据泄露、拒绝服务和数据篡改  
**投毒风险:** 1%  
**发现时间:** 2025-10-01  
**POC仓库:** [CVE-2025-56380](https://github.com/MoAlali/CVE-2025-56380)  

---

### [CVE-2025-56379](CVE-2025-56379-MoAlali_CVE-2025-56379.md) 🔴 ✅

**名称:** CVE-2025-56379 - ERPNext/Frappe Stored XSS  
**类型:** Stored Cross-Site Scripting (XSS)  
**风险:** 高危，可能导致数据泄露、会话劫持、恶意操作执行和拒绝服务。  
**投毒风险:** 10%  
**发现时间:** 2025-10-01  
**POC仓库:** [CVE-2025-56379](https://github.com/MoAlali/CVE-2025-56379)  

---

### [CVE-2025-32463](CVE-2025-32463-onniio_CVE-2025-32463.md) 🔴 ✅

**名称:** CVE-2025-32463-Sudo-本地提权  
**类型:** 本地提权  
**风险:** 高危，允许本地用户获取root权限  
**投毒风险:** 0%  
**发现时间:** 2025-10-01  
**POC仓库:** [CVE-2025-32463](https://github.com/onniio/CVE-2025-32463)  

---

### [CVE-2025-32463](CVE-2025-32463-onniio_CVE-2025-32463.md) 🔴 ✅

**名称:** CVE-2025-32463-Sudo-本地提权  
**类型:** 本地提权  
**风险:** 高危，本地用户可获取root权限  
**投毒风险:** 10%  
**发现时间:** 2025-10-01  
**POC仓库:** [CVE-2025-32463](https://github.com/onniio/CVE-2025-32463)  

---

### [CVE-2025-54677](CVE-2025-54677-quetuan03_CVE-2025-54677.md) 🔴 ✅

**名称:** CVE-2025-54677-meeting-scheduler-by-vcita-Arbitrary File Upload  
**类型:** Arbitrary File Upload  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-10-01  
**POC仓库:** [CVE-2025-54677](https://github.com/quetuan03/CVE-2025-54677)  

---

### [CVE-2025-58789](CVE-2025-58789-quetuan03_CVE-2025-58789.md) 🔴 ✅

**名称:** CVE-2025-58789-WP Full Stripe Free-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露  
**投毒风险:** 10%  
**发现时间:** 2025-10-01  
**POC仓库:** [CVE-2025-58789](https://github.com/quetuan03/CVE-2025-58789)  

---

### [CVE-2025-57926](CVE-2025-57926-quetuan03_CVE-2025-57926.md) 🟡 ✅

**名称:** CVE-2025-57926-Passster-Stored XSS  
**类型:** Stored XSS  
**风险:** 中危，可能导致用户会话劫持、信息泄露和恶意脚本执行  
**投毒风险:** 10%  
**发现时间:** 2025-10-01  
**POC仓库:** [CVE-2025-57926](https://github.com/quetuan03/CVE-2025-57926)  

---

### [CVE-2025-3248](CVE-2025-3248-Kiraly07_Demo_CVE-2025-3248.md) 🔴 ✅

**名称:** CVE-2025-3248 - Langflow RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，未经身份验证的远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-10-01  
**POC仓库:** [Demo_CVE-2025-3248](https://github.com/Kiraly07/Demo_CVE-2025-3248)  

---

### [CVE-2025-56588](CVE-2025-56588-PhDg1410_CVE-2025-56588.md) 🔴 ✅

**名称:** CVE-2025-56588 - Dolibarr ERP & CRM 21.0.1 - Computed Field Remote Code Execution  
**类型:** 远程代码执行  
**风险:** 高危，可导致服务器被完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-10-01  
**POC仓库:** [CVE-2025-56588](https://github.com/PhDg1410/CVE-2025-56588)  

---


## 🔍 快速查找

- [按CVE编号查找](../../by-cve/)
- [返回2025年总览](../README.md)
- [返回总索引](../../README.md)

---

*本文档由 VulnWatchdog 自动生成 @ 2025-11-26 13:32*
