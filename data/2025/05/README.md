# 2025年05月漏洞情报汇总

> 📅 统计周期: 2025-05-01 ~ 2025-05-30
> 📊 新增漏洞: **824** 个
> 🔥 高危漏洞: **698** 个

---

## 📊 漏洞类型分布

| 类型 | 数量 | 占比 |
|------|------|------|
| 远程代码执行 | 79 | 9.6% |
| 远程代码执行 (RCE) | 57 | 6.9% |
| 权限提升 | 55 | 6.7% |
| 目录遍历 | 37 | 4.5% |
| SQL注入 | 35 | 4.2% |
| 命令注入 | 32 | 3.9% |
| 本地权限提升 | 21 | 2.5% |
| 任意文件上传 | 19 | 2.3% |
| 信息泄露 | 17 | 2.1% |
| 本地提权 | 14 | 1.7% |

---

## 📋 详细列表

### [CVE-2025-12654](CVE-2025-12654-Quelvara_Anydesk-Exploit-CVE-2025-12654-RCE-Builder.md) 🔴 ✅

**名称:** CVE-2025-12654 Anydesk RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，允许攻击者在目标系统上执行恶意代码  
**投毒风险:** 30%  
**发现时间:** 2025-05-31  
**POC仓库:** [Anydesk-Exploit-CVE-2025-12654-RCE-Builder](https://github.com/Quelvara/Anydesk-Exploit-CVE-2025-12654-RCE-Builder)  

---

### [CVE-2025-3248](CVE-2025-3248-tiemio_RCE-CVE-2025-3248.md) 🔴 ✅

**名称:** CVE-2025-3248 Langflow 未授权远程代码执行  
**类型:** 代码注入  
**风险:** 高危，允许未授权的远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-05-31  
**POC仓库:** [RCE-CVE-2025-3248](https://github.com/tiemio/RCE-CVE-2025-3248)  

---

### [CVE-2024-9264](CVE-2024-9264-Cythonic1_CVE-2024-9264.md) 🔴 ✅

**名称:** CVE-2024-9264-Grafana-命令注入和文件包含  
**类型:** 命令注入和文件包含  
**风险:** 高危，可能导致远程代码执行和敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-05-31  
**POC仓库:** [CVE-2024-9264](https://github.com/Cythonic1/CVE-2024-9264)  

---

### [CVE-2024-9264](CVE-2024-9264-z3k0sec_File-Read-CVE-2024-9264.md) 🔴 ✅

**名称:** CVE-2024-9264-Grafana-命令注入和本地文件包含  
**类型:** 命令注入和本地文件包含  
**风险:** 高危，可能导致远程代码执行和敏感信息泄露  
**投毒风险:** 5%  
**发现时间:** 2025-05-31  
**POC仓库:** [File-Read-CVE-2024-9264](https://github.com/z3k0sec/File-Read-CVE-2024-9264)  

---

### [CVE-2024-9264](CVE-2024-9264-punitdarji_Grafana-CVE-2024-9264.md) 🔴 ✅

**名称:** CVE-2024-9264-Grafana-SQL表达式注入  
**类型:** 代码注入/本地文件包含  
**风险:** 高危，可能导致远程代码执行和敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-05-31  
**POC仓库:** [Grafana-CVE-2024-9264](https://github.com/punitdarji/Grafana-CVE-2024-9264)  

---

### [CVE-2024-9264](CVE-2024-9264-z3k0sec_CVE-2024-9264-RCE-Exploit.md)  ✅

**名称:** CVE-2024-9264-Grafana-远程代码执行  
**类型:** 远程代码执行  
**风险:** 严重，可能导致完全系统控制和数据泄露  
**投毒风险:** 10%  
**发现时间:** 2025-05-31  
**POC仓库:** [CVE-2024-9264-RCE-Exploit](https://github.com/z3k0sec/CVE-2024-9264-RCE-Exploit)  

---

### [CVE-2024-9264](CVE-2024-9264-nollium_CVE-2024-9264.md)  ✅

**名称:** CVE-2024-9264-Grafana-命令注入和文件包含  
**类型:** 命令注入和文件包含  
**风险:** 严重，可导致远程代码执行和敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-05-31  
**POC仓库:** [CVE-2024-9264](https://github.com/nollium/CVE-2024-9264)  

---

### [CVE-2011-0762](CVE-2011-0762-s3mPr1linux_CVE-2011-0762.md) 🟡 ✅

**名称:** CVE-2011-0762-vsftpd-DoS  
**类型:** 拒绝服务 (DoS)  
**风险:** 中危，导致CPU资源耗尽和进程槽耗尽  
**投毒风险:** 0%  
**发现时间:** 2025-05-31  
**POC仓库:** [CVE-2011-0762](https://github.com/s3mPr1linux/CVE-2011-0762)  

---

### [CVE-2011-0762](CVE-2011-0762-AndreyFreitass_CVE-2011-0762.md) 🟡 ✅

**名称:** CVE-2011-0762-vsftpd-拒绝服务  
**类型:** 拒绝服务 (DoS)  
**风险:** 中危，导致CPU资源耗尽和进程槽耗尽  
**投毒风险:** 0%  
**发现时间:** 2025-05-31  
**POC仓库:** [CVE-2011-0762](https://github.com/AndreyFreitass/CVE-2011-0762)  

---

### [CVE-2025-48827](CVE-2025-48827-wiseep_CVE-2025-48827.md) 🔴 ✅

**名称:** CVE-2025-48827-vBulletin-RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 5%  
**发现时间:** 2025-05-31  
**POC仓库:** [CVE-2025-48827](https://github.com/wiseep/CVE-2025-48827)  

---

### [CVE-2025-27590](CVE-2025-27590-fatkz_CVE-2025-27590.md) 🔴 ✅

**名称:** CVE-2025-27590 - Oxidized Web RANCID 迁移页面命令注入  
**类型:** 命令注入/路径遍历  
**风险:** 高危，可导致远程代码执行，控制服务器。  
**投毒风险:** 5%  
**发现时间:** 2025-05-31  
**POC仓库:** [CVE-2025-27590](https://github.com/fatkz/CVE-2025-27590)  

---

### [CVE-2025-30397](CVE-2025-30397-mbanyamer_CVE-2025-30397---Windows-Server-2025-JScript-RCE-Use-After-Free-.md) 🔴 ✅

**名称:** CVE-2025-30397 - Microsoft Scripting Engine Memory Corruption  
**类型:** 内存破坏/类型混淆  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-05-31  
**POC仓库:** [CVE-2025-30397---Windows-Server-2025-JScript-RCE-Use-After-Free-](https://github.com/mbanyamer/CVE-2025-30397---Windows-Server-2025-JScript-RCE-Use-After-Free-)  

---

### [CVE-2025-4631](CVE-2025-4631-Nxploited_CVE-2025-4631.md) 🔴 ✅

**名称:** CVE-2025-4631-Profitori-权限提升  
**类型:** 权限提升  
**风险:** 高危，未经身份验证的攻击者可以获得管理员权限  
**投毒风险:** 5%  
**发现时间:** 2025-05-31  
**POC仓库:** [CVE-2025-4631](https://github.com/Nxploited/CVE-2025-4631)  

---

### [CVE-2025-5287](CVE-2025-5287-wiseep_CVE-2025-5287.md) 🔴 ✅

**名称:** CVE-2025-5287-Likes and Dislikes Plugin-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 1%  
**发现时间:** 2025-05-31  
**POC仓库:** [CVE-2025-5287](https://github.com/wiseep/CVE-2025-5287)  

---

### [CVE-2025-20188](CVE-2025-20188-voyagken_CVE-2025-20188.md) 🔴 

**名称:** CVE-2025-20188: Cisco IOS XE WLC 未授权远程代码执行漏洞  
**类型:** 未授权远程代码执行  
**风险:** 高危，允许未授权远程攻击者上传任意文件，执行任意命令，获得root权限  
**投毒风险:** 20%  
**发现时间:** 2025-05-31  
**POC仓库:** [CVE-2025-20188](https://github.com/voyagken/CVE-2025-20188)  

---

### [CVE-2025-2995](CVE-2025-2995-huynguyen12536_CVE-2025-2995.md) 🟡 ✅

**名称:** CVE-2025-2995-Tenda FH1202-不当访问控制  
**类型:** 不当访问控制  
**风险:** 中危，可能导致未经授权的配置修改  
**投毒风险:** 10%  
**发现时间:** 2025-05-31  
**POC仓库:** [CVE-2025-2995](https://github.com/huynguyen12536/CVE-2025-2995)  

---

### [CVE-2025-47577](CVE-2025-47577-Yucaerin_CVE-2025-47577.md) 🔴 ✅

**名称:** CVE-2025-47577 - WordPress TI WooCommerce Wishlist Arbitrary File Upload  
**类型:** 任意文件上传  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-05-30  
**POC仓库:** [CVE-2025-47577](https://github.com/Yucaerin/CVE-2025-47577)  

---

### [CVE-2024-7399](CVE-2024-7399-davidxbors_CVE-2024-7399-POC.md) 🔴 ✅

**名称:** CVE-2024-7399 - Samsung MagicINFO 9 Server 路径遍历与任意文件写入  
**类型:** 路径遍历 (CWE-22) / 任意文件写入 (CWE-434)  
**风险:** 高危，允许未经身份验证的攻击者以系统权限写入任意文件，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-05-30  
**POC仓库:** [CVE-2024-7399-POC](https://github.com/davidxbors/CVE-2024-7399-POC)  

---

### [CVE-2022-0847](CVE-2022-0847-pashayogi_DirtyPipe.md) 🔴 ✅

**名称:** CVE-2022-0847 - Dirty Pipe 本地权限提升  
**类型:** 本地权限提升  
**风险:** 高危，可导致完全控制系统  
**投毒风险:** 10%  
**发现时间:** 2025-05-30  
**POC仓库:** [DirtyPipe](https://github.com/pashayogi/DirtyPipe)  

---

### [CVE-2022-0847](CVE-2022-0847-byteReaper77_Dirty-Pipe.md) 🔴 ✅

**名称:** CVE-2022-0847 - Dirty Pipe  
**类型:** 本地权限提升  
**风险:** 高危，允许非特权用户覆盖只读文件并提升权限  
**投毒风险:** 5%  
**发现时间:** 2025-05-30  
**POC仓库:** [Dirty-Pipe](https://github.com/byteReaper77/Dirty-Pipe)  

---

### [CVE-2022-0847](CVE-2022-0847-JlSakuya_CVE-2022-0847-container-escape.md) 🔴 ✅

**名称:** CVE-2022-0847 Dirty Pipe 本地提权漏洞  
**类型:** 本地提权  
**风险:** 高危，可导致本地用户提升权限至 root  
**投毒风险:** 10%  
**发现时间:** 2025-05-30  
**POC仓库:** [CVE-2022-0847-container-escape](https://github.com/JlSakuya/CVE-2022-0847-container-escape)  

---

### [CVE-2022-0847](CVE-2022-0847-jonathanbest7_cve-2022-0847.md) 🔴 

**名称:** CVE-2022-0847  
**类型:** Dirty Pipe 本地提权漏洞  
**风险:** 高危，可导致本地权限提升  
**投毒风险:** 5%  
**发现时间:** 2025-05-30  
**POC仓库:** [cve-2022-0847](https://github.com/jonathanbest7/cve-2022-0847)  

---

### [CVE-2022-0847](CVE-2022-0847-AlexisAhmed_CVE-2022-0847-DirtyPipe-Exploits.md) 🔴 ✅

**名称:** CVE-2022-0847 Dirty Pipe 本地提权漏洞  
**类型:** 本地权限提升  
**风险:** 高危，可导致权限提升和任意文件覆盖  
**投毒风险:** 10%  
**发现时间:** 2025-05-30  
**POC仓库:** [CVE-2022-0847-DirtyPipe-Exploits](https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits)  

---

### [CVE-2022-0847](CVE-2022-0847-basharkey_CVE-2022-0847-dirty-pipe-checker.md) 🔴 ✅

**名称:** CVE-2022-0847 Dirty Pipe 本地提权漏洞检测脚本  
**类型:** 本地提权  
**风险:** 高危，允许本地用户覆盖只读文件并提升权限  
**投毒风险:** 0%  
**发现时间:** 2025-05-30  
**POC仓库:** [CVE-2022-0847-dirty-pipe-checker](https://github.com/basharkey/CVE-2022-0847-dirty-pipe-checker)  

---

### [CVE-2022-0847](CVE-2022-0847-0xeremus_dirty-pipe-poc.md) 🔴 ✅

**名称:** CVE-2022-0847 Dirty Pipe 本地提权  
**类型:** 本地提权  
**风险:** 高危，可导致本地用户提升为root权限  
**投毒风险:** 10%  
**发现时间:** 2025-05-30  
**POC仓库:** [dirty-pipe-poc](https://github.com/0xeremus/dirty-pipe-poc)  

---

### [CVE-2022-0847](CVE-2022-0847-ih3na_debian11-dirty_pipe-patcher.md) 🔴 ✅

**名称:** CVE-2022-0847-Dirty Pipe  
**类型:** 本地权限提升  
**风险:** 高危，可导致任意文件覆盖和权限提升  
**投毒风险:** 0%  
**发现时间:** 2025-05-30  
**POC仓库:** [debian11-dirty_pipe-patcher](https://github.com/ih3na/debian11-dirty_pipe-patcher)  

---

### [CVE-2022-0847](CVE-2022-0847-joeymeech_CVE-2022-0847-Exploit-Implementation.md) 🔴 ✅

**名称:** CVE-2022-0847 Dirty Pipe本地提权  
**类型:** 本地权限提升  
**风险:** 高危，可导致本地用户权限提升至root  
**投毒风险:** 10%  
**发现时间:** 2025-05-30  
**POC仓库:** [CVE-2022-0847-Exploit-Implementation](https://github.com/joeymeech/CVE-2022-0847-Exploit-Implementation)  

---

### [CVE-2022-0847](CVE-2022-0847-mutur4_CVE-2022-0847.md) 🔴 ✅

**名称:** CVE-2022-0847 (Dirty Pipe)  
**类型:** 本地权限提升  
**风险:** 高危，允许非特权用户覆盖只读文件，导致权限提升  
**投毒风险:** 0%  
**发现时间:** 2025-05-30  
**POC仓库:** [CVE-2022-0847](https://github.com/mutur4/CVE-2022-0847)  

---

### [CVE-2022-0847](CVE-2022-0847-n3rada_DirtyPipe.md) 🔴 ✅

**名称:** CVE-2022-0847 (Dirty Pipe)  
**类型:** 本地权限提升  
**风险:** 高危，可导致普通用户提升至root权限  
**投毒风险:** 10%  
**发现时间:** 2025-05-30  
**POC仓库:** [DirtyPipe](https://github.com/n3rada/DirtyPipe)  

---

### [CVE-2022-0847](CVE-2022-0847-ayushx007_CVE-2022-0847-dirty-pipe-checker.md) 🔴 ✅

**名称:** CVE-2022-0847 Dirty Pipe 本地提权漏洞  
**类型:** 本地权限提升  
**风险:** 高危，本地用户可利用该漏洞覆盖只读文件并提升权限  
**投毒风险:** 0%  
**发现时间:** 2025-05-30  
**POC仓库:** [CVE-2022-0847-dirty-pipe-checker](https://github.com/ayushx007/CVE-2022-0847-dirty-pipe-checker)  

---

### [CVE-2022-0847](CVE-2022-0847-h4ckm310n_CVE-2022-0847-eBPF.md) 🔴 ✅

**名称:** CVE-2022-0847 (Dirty Pipe)  
**类型:** 本地权限提升  
**风险:** 高危，允许非特权本地用户覆盖只读文件并提升权限。  
**投毒风险:** 10%  
**发现时间:** 2025-05-30  
**POC仓库:** [CVE-2022-0847-eBPF](https://github.com/h4ckm310n/CVE-2022-0847-eBPF)  

---

### [CVE-2022-0847](CVE-2022-0847-ayushx007_CVE-2022-0847-DirtyPipe-Exploits.md) 🔴 ✅

**名称:** CVE-2022-0847-Dirty Pipe  
**类型:** 本地权限提升  
**风险:** 高危，允许非特权用户覆盖只读文件，提升权限至root  
**投毒风险:** 10%  
**发现时间:** 2025-05-30  
**POC仓库:** [CVE-2022-0847-DirtyPipe-Exploits](https://github.com/ayushx007/CVE-2022-0847-DirtyPipe-Exploits)  

---

### [CVE-2022-0847](CVE-2022-0847-letsr00t_CVE-2022-0847.md) 🔴 ✅

**名称:** CVE-2022-0847 Dirty Pipe  
**类型:** 本地权限提升  
**风险:** 高危，可能导致本地权限提升至 root  
**投毒风险:** 0%  
**发现时间:** 2025-05-30  
**POC仓库:** [CVE-2022-0847](https://github.com/letsr00t/CVE-2022-0847)  

---

### [CVE-2022-0847](CVE-2022-0847-xsxtw_CVE-2022-0847.md) 🔴 ✅

**名称:** CVE-2022-0847 Dirty Pipe 本地提权漏洞  
**类型:** 本地提权  
**风险:** 高危，可导致普通用户提升为 root 权限  
**投毒风险:** 5%  
**发现时间:** 2025-05-30  
**POC仓库:** [CVE-2022-0847](https://github.com/xsxtw/CVE-2022-0847)  

---

### [CVE-2022-0847](CVE-2022-0847-solomon12354_LockingGirl-----CVE-2022-0847-Dirty_Pipe_virus.md) 🔴 ✅

**名称:** CVE-2022-0847 Dirty Pipe 本地提权漏洞  
**类型:** 本地权限提升  
**风险:** 高危，可使普通用户获得root权限  
**投毒风险:** 5%  
**发现时间:** 2025-05-30  
**POC仓库:** [LockingGirl-----CVE-2022-0847-Dirty_Pipe_virus](https://github.com/solomon12354/LockingGirl-----CVE-2022-0847-Dirty_Pipe_virus)  

---

### [CVE-2022-0847](CVE-2022-0847-muhammad1596_CVE-2022-0847-dirty-pipe-checker.md) 🔴 ✅

**名称:** CVE-2022-0847-Dirty Pipe  
**类型:** 本地提权  
**风险:** 高危，可能导致任意文件覆盖和权限提升  
**投毒风险:** 10%  
**发现时间:** 2025-05-30  
**POC仓库:** [CVE-2022-0847-dirty-pipe-checker](https://github.com/muhammad1596/CVE-2022-0847-dirty-pipe-checker)  

---

### [CVE-2022-0847](CVE-2022-0847-muhammad1596_CVE-2022-0847-DirtyPipe-Exploits.md) 🔴 ✅

**名称:** CVE-2022-0847 - Dirty Pipe 本地提权漏洞  
**类型:** 本地权限提升  
**风险:** 高危，可导致普通用户获取 root 权限  
**投毒风险:** 0%  
**发现时间:** 2025-05-30  
**POC仓库:** [CVE-2022-0847-DirtyPipe-Exploits](https://github.com/muhammad1596/CVE-2022-0847-DirtyPipe-Exploits)  

---

### [CVE-2022-0847](CVE-2022-0847-karanlvm_DirtyPipe-Exploit.md) 🔴 ✅

**名称:** CVE-2022-0847 (Dirty Pipe)  
**类型:** 本地权限提升  
**风险:** 高危，可导致root权限获取  
**投毒风险:** 5%  
**发现时间:** 2025-05-30  
**POC仓库:** [DirtyPipe-Exploit](https://github.com/karanlvm/DirtyPipe-Exploit)  

---

### [CVE-2022-0847](CVE-2022-0847-arttnba3_CVE-2022-0847.md) 🔴 ✅

**名称:** CVE-2022-0847 (Dirty Pipe)  
**类型:** 本地权限提升  
**风险:** 高危，可导致任意代码执行和完全系统控制  
**投毒风险:** 10%  
**发现时间:** 2025-05-30  
**POC仓库:** [CVE-2022-0847](https://github.com/arttnba3/CVE-2022-0847)  

---

### [CVE-2022-0847](CVE-2022-0847-JustinYe377_CTF-CVE-2022-0847.md) 🔴 ✅

**名称:** CVE-2022-0847 Dirty Pipe 本地提权  
**类型:** 本地提权  
**风险:** 高危，可能导致本地普通用户提升至root权限  
**投毒风险:** 5%  
**发现时间:** 2025-05-30  
**POC仓库:** [CTF-CVE-2022-0847](https://github.com/JustinYe377/CTF-CVE-2022-0847)  

---

### [CVE-2022-0847](CVE-2022-0847-mithunmadhukuttan_Dirty-Pipe-Exploit.md) 🔴 ✅

**名称:** CVE-2022-0847 - Dirty Pipe 本地提权漏洞  
**类型:** 本地提权  
**风险:** 高危，允许本地用户覆盖只读文件，从而提升权限。  
**投毒风险:** 10%  
**发现时间:** 2025-05-30  
**POC仓库:** [Dirty-Pipe-Exploit](https://github.com/mithunmadhukuttan/Dirty-Pipe-Exploit)  

---

### [CVE-2022-0847](CVE-2022-0847-Asbatel_CBDS_CVE-2022-0847_POC.md) 🔴 ✅

**名称:** CVE-2022-0847-Dirty Pipe  
**类型:** 本地权限提升  
**风险:** 高危，允许非特权用户覆盖只读文件，提升权限  
**投毒风险:** 10%  
**发现时间:** 2025-05-30  
**POC仓库:** [CBDS_CVE-2022-0847_POC](https://github.com/Asbatel/CBDS_CVE-2022-0847_POC)  

---

### [CVE-2022-0847](CVE-2022-0847-Mephierr_DirtyPipe_exploit.md) 🔴 ✅

**名称:** CVE-2022-0847 (Dirty Pipe) Local Privilege Escalation  
**类型:** 本地权限提升  
**风险:** 高危，可获取root权限  
**投毒风险:** 0%  
**发现时间:** 2025-05-30  
**POC仓库:** [DirtyPipe_exploit](https://github.com/Mephierr/DirtyPipe_exploit)  

---

### [CVE-2022-0847](CVE-2022-0847-RogelioPumajulca_CVE-2022-0847.md) 🔴 ✅

**名称:** CVE-2022-0847 (Dirty Pipe) 本地提权漏洞  
**类型:** 本地提权  
**风险:** 高危，可导致普通用户提升为root权限  
**投毒风险:** 1%  
**发现时间:** 2025-05-30  
**POC仓库:** [CVE-2022-0847](https://github.com/RogelioPumajulca/CVE-2022-0847)  

---

### [CVE-2022-0847](CVE-2022-0847-cypherlobo_DirtyPipe-BSI.md) 🔴 ✅

**名称:** CVE-2022-0847 - Dirty Pipe 本地提权漏洞  
**类型:** 本地提权  
**风险:** 高危，可能导致本地权限提升至root  
**投毒风险:** 0%  
**发现时间:** 2025-05-30  
**POC仓库:** [DirtyPipe-BSI](https://github.com/cypherlobo/DirtyPipe-BSI)  

---

### [CVE-2025-29093](CVE-2025-29093-FraMarcuccio_CVE-2025-29093-Arbitrary-File-Upload.md) 🟡 ✅

**名称:** CVE-2025-29093-Motivian CMS Arbitrary File Upload  
**类型:** Arbitrary File Upload  
**风险:** 中危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-05-30  
**POC仓库:** [CVE-2025-29093-Arbitrary-File-Upload](https://github.com/FraMarcuccio/CVE-2025-29093-Arbitrary-File-Upload)  

---

### [CVE-2025-29094](CVE-2025-29094-FraMarcuccio_CVE-2025-29094-Multiple-Stored-Cross-Site-Scripting-XSS.md) 🟡 ✅

**名称:** CVE-2025-29094-Motivian CMS-存储型XSS  
**类型:** 存储型XSS  
**风险:** 中危，允许远程攻击者在受害者浏览器中执行任意JavaScript代码  
**投毒风险:** 0%  
**发现时间:** 2025-05-30  
**POC仓库:** [CVE-2025-29094-Multiple-Stored-Cross-Site-Scripting-XSS](https://github.com/FraMarcuccio/CVE-2025-29094-Multiple-Stored-Cross-Site-Scripting-XSS)  

---

### [CVE-2024-21413](CVE-2024-21413-MQKGitHub_Moniker-Link-CVE-2024-21413.md) 🔴 ✅

**名称:** CVE-2024-21413 - Microsoft Outlook Remote Code Execution Vulnerability  
**类型:** 远程代码执行 (RCE) / NTLM Hash Leak  
**风险:** 高危，可能导致远程代码执行、NTLM凭据泄露、横向移动和权限提升  
**投毒风险:** 10%  
**发现时间:** 2025-05-30  
**POC仓库:** [Moniker-Link-CVE-2024-21413](https://github.com/MQKGitHub/Moniker-Link-CVE-2024-21413)  

---

### [CVE-2020-1472](CVE-2020-1472-Anonymous-Family_CVE-2020-1472.md) 🔴 ✅

**名称:** CVE-2020-1472 Zerologon 特权提升漏洞  
**类型:** 特权提升  
**风险:** 高危，可能导致域控制器的完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-05-30  
**POC仓库:** [CVE-2020-1472](https://github.com/Anonymous-Family/CVE-2020-1472)  

---

### [CVE-2020-1472](CVE-2020-1472-RicYaben_CVE-2020-1472-LAB.md) 🔴 ✅

**名称:** CVE-2020-1472 Zerologon Netlogon 权限提升漏洞  
**类型:** 权限提升  
**风险:** 高危，可能导致域控被接管  
**投毒风险:** 1%  
**发现时间:** 2025-05-30  
**POC仓库:** [CVE-2020-1472-LAB](https://github.com/RicYaben/CVE-2020-1472-LAB)  

---

### [CVE-2020-1472](CVE-2020-1472-PakwanSK_Simulating-and-preventing-Zerologon-CVE-2020-1472-vulnerability-attacks..md) 🔴 ✅

**名称:** CVE-2020-1472 (Zerologon)  
**类型:** 权限提升  
**风险:** 高危，可导致域控制器的完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-05-30  
**POC仓库:** [Simulating-and-preventing-Zerologon-CVE-2020-1472-vulnerability-attacks.](https://github.com/PakwanSK/Simulating-and-preventing-Zerologon-CVE-2020-1472-vulnerability-attacks.)  

---

### [CVE-2020-0796](CVE-2020-0796-tdevworks_CVE-2020-0796-SMBGhost-Exploit-Demo.md) 🔴 ✅

**名称:** CVE-2020-0796 (SMBGhost)  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，未经身份验证的攻击者可以远程执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-05-30  
**POC仓库:** [CVE-2020-0796-SMBGhost-Exploit-Demo](https://github.com/tdevworks/CVE-2020-0796-SMBGhost-Exploit-Demo)  

---

### [CVE-2025-5329](CVE-2025-5329-sahici_CVE-2025-5329.md)  ✅

**名称:** CVE-2025-5329  
**类型:** 未知  
**风险:** 未知  
**投毒风险:** 5%  
**发现时间:** 2025-05-30  
**POC仓库:** [CVE-2025-5329](https://github.com/sahici/CVE-2025-5329)  

---

### [CVE-2025-5319](CVE-2025-5319-sahici_CVE-2025-5319.md)  ✅

**名称:** CVE-2025-5319  
**类型:** 未知  
**风险:** 待评估  
**投毒风险:** 10%  
**发现时间:** 2025-05-30  
**POC仓库:** [CVE-2025-5319](https://github.com/sahici/CVE-2025-5319)  

---

### [CVE-2020-1472](CVE-2020-1472-itssmikefm_CVE-2020-1472.md) 🔴 ✅

**名称:** CVE-2020-1472 Zerologon 权限提升漏洞  
**类型:** 权限提升  
**风险:** 高危，允许未经身份验证的攻击者获取域管理员权限  
**投毒风险:** 5%  
**发现时间:** 2025-05-30  
**POC仓库:** [CVE-2020-1472](https://github.com/itssmikefm/CVE-2020-1472)  

---

### [CVE-2020-1472](CVE-2020-1472-puckiestyle_CVE-2020-1472.md) 🔴 ✅

**名称:** CVE-2020-1472 (Zerologon) Netlogon 权限提升漏洞  
**类型:** 权限提升  
**风险:** 高危，可能导致域控制器的完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-05-30  
**POC仓库:** [CVE-2020-1472](https://github.com/puckiestyle/CVE-2020-1472)  

---

### [CVE-2020-1472](CVE-2020-1472-Fa1c0n35_CVE-2020-1472-02-.md) 🔴 ✅

**名称:** CVE-2020-1472 (Zerologon)  
**类型:** 权限提升  
**风险:** 高危，可导致域管理员权限被获取  
**投毒风险:** 10%  
**发现时间:** 2025-05-30  
**POC仓库:** [CVE-2020-1472-02-](https://github.com/Fa1c0n35/CVE-2020-1472-02-)  

---

### [CVE-2020-1472](CVE-2020-1472-Fa1c0n35_SecuraBV-CVE-2020-1472.md) 🔴 ✅

**名称:** CVE-2020-1472 Zerologon 本地提权漏洞  
**类型:** 权限提升  
**风险:** 高危，允许未经身份验证的攻击者获得域管理员权限  
**投毒风险:** 5%  
**发现时间:** 2025-05-30  
**POC仓库:** [SecuraBV-CVE-2020-1472](https://github.com/Fa1c0n35/SecuraBV-CVE-2020-1472)  

---

### [CVE-2020-1472](CVE-2020-1472-CPO-EH_CVE-2020-1472_ZeroLogonChecker.md) 🔴 ✅

**名称:** CVE-2020-1472 (Zerologon) 漏洞检测  
**类型:** 权限提升  
**风险:** 高危，可能导致域控制器的完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-05-30  
**POC仓库:** [CVE-2020-1472_ZeroLogonChecker](https://github.com/CPO-EH/CVE-2020-1472_ZeroLogonChecker)  

---

### [CVE-2020-1472](CVE-2020-1472-TheJoyOfHacking_SecuraBV-CVE-2020-1472.md) 🔴 ✅

**名称:** CVE-2020-1472 (Zerologon): Netlogon 特权提升漏洞  
**类型:** 特权提升  
**风险:** 高危，可能导致域管理员权限被获取  
**投毒风险:** 1%  
**发现时间:** 2025-05-30  
**POC仓库:** [SecuraBV-CVE-2020-1472](https://github.com/TheJoyOfHacking/SecuraBV-CVE-2020-1472)  

---

### [CVE-2020-1472](CVE-2020-1472-TheJoyOfHacking_dirkjanm-CVE-2020-1472.md) 🔴 ✅

**名称:** CVE-2020-1472 (Zerologon)  
**类型:** 权限提升  
**风险:** 高危，可能导致域接管  
**投毒风险:** 10%  
**发现时间:** 2025-05-30  
**POC仓库:** [dirkjanm-CVE-2020-1472](https://github.com/TheJoyOfHacking/dirkjanm-CVE-2020-1472)  

---

### [CVE-2020-1472](CVE-2020-1472-Anonymous-Family_Zero-day-scanning.md) 🔴 ✅

**名称:** CVE-2020-1472 Zerologon 权限提升漏洞  
**类型:** 权限提升  
**风险:** 高危，可能导致域控制器的完全控制  
**投毒风险:** 5%  
**发现时间:** 2025-05-30  
**POC仓库:** [Zero-day-scanning](https://github.com/Anonymous-Family/Zero-day-scanning)  

---

### [CVE-2020-1472](CVE-2020-1472-carlos55ml_zerologon.md) 🔴 ✅

**名称:** CVE-2020-1472 Zerologon Netlogon特权提升漏洞  
**类型:** 特权提升  
**风险:** 高危，可能导致域控制器的完全接管  
**投毒风险:** 10%  
**发现时间:** 2025-05-30  
**POC仓库:** [zerologon](https://github.com/carlos55ml/zerologon)  

---

### [CVE-2020-1472](CVE-2020-1472-B34MR_zeroscan.md) 🔴 ✅

**名称:** CVE-2020-1472 (Zerologon)  
**类型:** 权限提升  
**风险:** 高危，允许未经身份验证的攻击者获得域管理员权限。  
**投毒风险:** 10%  
**发现时间:** 2025-05-30  
**POC仓库:** [zeroscan](https://github.com/B34MR/zeroscan)  

---

### [CVE-2020-1472](CVE-2020-1472-sho-luv_zerologon.md) 🔴 ✅

**名称:** CVE-2020-1472 Zerologon  
**类型:** 权限提升  
**风险:** 高危，可导致域控被完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-05-30  
**POC仓库:** [zerologon](https://github.com/sho-luv/zerologon)  

---

### [CVE-2020-1472](CVE-2020-1472-Rvn0xsy_ZeroLogon.md) 🔴 ✅

**名称:** CVE-2020-1472 Zerologon  
**类型:** 权限提升  
**风险:** 高危，可能导致域管理员权限获取  
**投毒风险:** 10%  
**发现时间:** 2025-05-30  
**POC仓库:** [ZeroLogon](https://github.com/Rvn0xsy/ZeroLogon)  

---

### [CVE-2020-1472](CVE-2020-1472-likeww_MassZeroLogon.md) 🔴 ✅

**名称:** CVE-2020-1472 (Zerologon) Netlogon 特权提升漏洞  
**类型:** 特权提升  
**风险:** 高危，允许未认证的攻击者获取域管理员权限，完全控制域。  
**投毒风险:** 5%  
**发现时间:** 2025-05-30  
**POC仓库:** [MassZeroLogon](https://github.com/likeww/MassZeroLogon)  

---

### [CVE-2020-1472](CVE-2020-1472-guglia001_MassZeroLogon.md) 🔴 ✅

**名称:** CVE-2020-1472-Zerologon  
**类型:** 权限提升  
**风险:** 高危，可导致域控被完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-05-30  
**POC仓库:** [MassZeroLogon](https://github.com/guglia001/MassZeroLogon)  

---

### [CVE-2020-1472](CVE-2020-1472-dr4g0n23_CVE-2020-1472.md) 🔴 ✅

**名称:** CVE-2020-1472 Zerologon 本地提权漏洞  
**类型:** 权限提升  
**风险:** 高危，可能导致域管理员权限被获取，完全控制域环境  
**投毒风险:** 10%  
**发现时间:** 2025-05-30  
**POC仓库:** [CVE-2020-1472](https://github.com/dr4g0n23/CVE-2020-1472)  

---

### [CVE-2020-1472](CVE-2020-1472-sv3nbeast_CVE-2020-1472.md) 🔴 ✅

**名称:** CVE-2020-1472 (Zerologon) Netlogon 特权提升漏洞  
**类型:** 特权提升  
**风险:** 高危，可导致域控制器的完全接管  
**投毒风险:** 1%  
**发现时间:** 2025-05-30  
**POC仓库:** [CVE-2020-1472](https://github.com/sv3nbeast/CVE-2020-1472)  

---

### [CVE-2020-1472](CVE-2020-1472-bb00_zer0dump.md) 🔴 ✅

**名称:** CVE-2020-1472 (Zerologon) 权限提升漏洞  
**类型:** 权限提升  
**风险:** 高危，可能导致域控制器的完全接管  
**投毒风险:** 10%  
**发现时间:** 2025-05-30  
**POC仓库:** [zer0dump](https://github.com/bb00/zer0dump)  

---

### [CVE-2020-1472](CVE-2020-1472-Akash7350_CVE-2020-1472.md) 🔴 ✅

**名称:** CVE-2020-1472-Zerologon-特权提升  
**类型:** 特权提升  
**风险:** 高危，可能导致域控制器的完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-05-30  
**POC仓库:** [CVE-2020-1472](https://github.com/Akash7350/CVE-2020-1472)  

---

### [CVE-2020-1472](CVE-2020-1472-zeronetworks_zerologon.md) 🔴 ✅

**名称:** CVE-2020-1472 Zerologon 本地提权漏洞  
**类型:** 特权提升  
**风险:** 高危，可能导致域控被完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-05-30  
**POC仓库:** [zerologon](https://github.com/zeronetworks/zerologon)  

---

### [CVE-2020-1472](CVE-2020-1472-SecuraBV_CVE-2020-1472.md) 🔴 ✅

**名称:** CVE-2020-1472 - Netlogon Elevation of Privilege Vulnerability (Zerologon)  
**类型:** 权限提升  
**风险:** 高危，可能导致域管理员权限被获取，控制整个域  
**投毒风险:** 5%  
**发现时间:** 2025-05-30  
**POC仓库:** [CVE-2020-1472](https://github.com/SecuraBV/CVE-2020-1472)  

---

### [CVE-2020-1472](CVE-2020-1472-c3rrberu5_ZeroLogon-to-Shell.md) 🔴 ✅

**名称:** CVE-2020-1472 Zerologon权限提升漏洞  
**类型:** 权限提升  
**风险:** 高危，允许未授权的攻击者接管域控制器  
**投毒风险:** 10%  
**发现时间:** 2025-05-30  
**POC仓库:** [ZeroLogon-to-Shell](https://github.com/c3rrberu5/ZeroLogon-to-Shell)  

---

### [CVE-2020-1472](CVE-2020-1472-logg-1_0logon.md) 🔴 ✅

**名称:** CVE-2020-1472 (Zerologon)  
**类型:** 权限提升  
**风险:** 高危，可能导致域控制器的完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-05-30  
**POC仓库:** [0logon](https://github.com/logg-1/0logon)  

---

### [CVE-2020-1472](CVE-2020-1472-whoami-chmod777_Zerologon-Attack-CVE-2020-1472-POC.md) 🔴 ✅

**名称:** CVE-2020-1472 (Zerologon)  
**类型:** 权限提升  
**风险:** 高危，可导致域控被完全控制  
**投毒风险:** 5%  
**发现时间:** 2025-05-30  
**POC仓库:** [Zerologon-Attack-CVE-2020-1472-POC](https://github.com/whoami-chmod777/Zerologon-Attack-CVE-2020-1472-POC)  

---

### [CVE-2020-1472](CVE-2020-1472-JolynNgSC_Zerologon_CVE-2020-1472.md) 🔴 ✅

**名称:** CVE-2020-1472 Netlogon Elevation of Privilege Vulnerability (Zerologon)  
**类型:** 权限提升  
**风险:** 高危，允许未经身份验证的攻击者获取域管理员权限并完全控制域  
**投毒风险:** 10%  
**发现时间:** 2025-05-30  
**POC仓库:** [Zerologon_CVE-2020-1472](https://github.com/JolynNgSC/Zerologon_CVE-2020-1472)  

---

### [CVE-2020-1472](CVE-2020-1472-blackh00d_zerologon-poc.md) 🔴 ✅

**名称:** CVE-2020-1472 Zerologon Netlogon 特权提升漏洞  
**类型:** 特权提升  
**风险:** 高危，允许未经身份验证的攻击者获取域管理员权限，完全控制域环境  
**投毒风险:** 1%  
**发现时间:** 2025-05-30  
**POC仓库:** [zerologon-poc](https://github.com/blackh00d/zerologon-poc)  

---

### [CVE-2020-1472](CVE-2020-1472-TuanCui22_ZerologonWithImpacket-CVE2020-1472.md) 🔴 ✅

**名称:** CVE-2020-1472 (Zerologon)  
**类型:** 特权提升  
**风险:** 高危，可能导致域控被完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-05-30  
**POC仓库:** [ZerologonWithImpacket-CVE2020-1472](https://github.com/TuanCui22/ZerologonWithImpacket-CVE2020-1472)  

---

### [CVE-2020-1472](CVE-2020-1472-tdevworks_CVE-2020-1472-ZeroLogon-Demo-Detection-Mitigation.md) 🔴 ✅

**名称:** CVE-2020-1472 (Zerologon) Netlogon 权限提升漏洞  
**类型:** 权限提升  
**风险:** 高危，可能导致域控制器的完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-05-30  
**POC仓库:** [CVE-2020-1472-ZeroLogon-Demo-Detection-Mitigation](https://github.com/tdevworks/CVE-2020-1472-ZeroLogon-Demo-Detection-Mitigation)  

---

### [CVE-2024-41570](CVE-2024-41570-chebuya_Havoc-C2-SSRF-poc.md) 🔴 ✅

**名称:** CVE-2024-41570-Havoc-C2-SSRF  
**类型:** 服务器端请求伪造 (SSRF)  
**风险:** 高危，可能导致敏感信息泄露、内网探测、拒绝服务，甚至远程代码执行。  
**投毒风险:** 10%  
**发现时间:** 2025-05-30  
**POC仓库:** [Havoc-C2-SSRF-poc](https://github.com/chebuya/Havoc-C2-SSRF-poc)  

---

### [CVE-2024-41570](CVE-2024-41570-HimmeL-Byte_CVE-2024-41570-SSRF-RCE.md) 🔴 ✅

**名称:** CVE-2024-41570-Havoc-C2-SSRF  
**类型:** 服务器端请求伪造 (SSRF)  
**风险:** 高危，允许未授权的攻击者从团队服务器发送任意网络流量，可能导致内网信息泄露、远程代码执行等。  
**投毒风险:** 10%  
**发现时间:** 2025-05-30  
**POC仓库:** [CVE-2024-41570-SSRF-RCE](https://github.com/HimmeL-Byte/CVE-2024-41570-SSRF-RCE)  

---

### [CVE-2024-41570](CVE-2024-41570-sebr-dev_Havoc-C2-SSRF-to-RCE.md) 🔴 ✅

**名称:** CVE-2024-41570-Havoc C2-SSRF+RCE  
**类型:** SSRF+RCE  
**风险:** 高危，可能导致服务器信息泄露，远程代码执行，以及发起对内网的攻击  
**投毒风险:** 5%  
**发现时间:** 2025-05-30  
**POC仓库:** [Havoc-C2-SSRF-to-RCE](https://github.com/sebr-dev/Havoc-C2-SSRF-to-RCE)  

---

### [CVE-2024-41570](CVE-2024-41570-thisisveryfunny_CVE-2024-41570-Havoc-C2-RCE.md) 🔴 ✅

**名称:** CVE-2024-41570-Havoc-C2-SSRF  
**类型:** 服务器端请求伪造 (SSRF)  
**风险:** 高危，可能导致敏感信息泄露、内网探测、远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-05-30  
**POC仓库:** [CVE-2024-41570-Havoc-C2-RCE](https://github.com/thisisveryfunny/CVE-2024-41570-Havoc-C2-RCE)  

---

### [CVE-2024-41570](CVE-2024-41570-kit4py_CVE-2024-41570.md) 🔴 ✅

**名称:** CVE-2024-41570 - Havoc C2 未授权SSRF漏洞  
**类型:** 服务器端请求伪造 (SSRF)  
**风险:** 高危，可能导致信息泄露、内网渗透、远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-05-30  
**POC仓库:** [CVE-2024-41570](https://github.com/kit4py/CVE-2024-41570)  

---

### [CVE-2023-49496](CVE-2023-49496-HuangYanQwQ_CVE-2023-49496_PoC.md)  

**名称:** 未知漏洞 - GPL License分析  
**类型:** 许可证  
**风险:** 低危，主要涉及软件许可证合规性  
**投毒风险:** 0%  
**发现时间:** 2025-05-30  
**POC仓库:** [CVE-2023-49496_PoC](https://github.com/HuangYanQwQ/CVE-2023-49496_PoC)  

---

### [CVE-2024-11234](CVE-2024-11234-cyivor_CVE-2024-11234.md) 🟡 ✅

**名称:** CVE-2024-11234-PHP HTTP Request Smuggling  
**类型:** HTTP请求走私  
**风险:** 中危，可能导致未经授权的资源访问  
**投毒风险:** 0%  
**发现时间:** 2025-05-30  
**POC仓库:** [CVE-2024-11234](https://github.com/cyivor/CVE-2024-11234)  

---

### [CVE-2021-26828](CVE-2021-26828-hev0x_CVE-2021-26828_ScadaBR_RCE.md) 🔴 ✅

**名称:** CVE-2021-26828-ScadaBR-任意文件上传导致远程代码执行  
**类型:** 任意文件上传  
**风险:** 高危，可能导致远程代码执行，控制整个系统  
**投毒风险:** 10%  
**发现时间:** 2025-05-30  
**POC仓库:** [CVE-2021-26828_ScadaBR_RCE](https://github.com/hev0x/CVE-2021-26828_ScadaBR_RCE)  

---

### [CVE-2021-26828](CVE-2021-26828-ridpath_CVE-2021-26828-Ultimate.md) 🔴 ✅

**名称:** CVE-2021-26828-ScadaBR-RCE  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 5%  
**发现时间:** 2025-05-30  
**POC仓库:** [CVE-2021-26828-Ultimate](https://github.com/ridpath/CVE-2021-26828-Ultimate)  

---

### [CVE-2016-20012](CVE-2016-20012-aztec-eagle_cve-2016-20012.md)  ✅

**名称:** CVE-2016-20012-OpenSSH-用户名枚举  
**类型:** 信息泄露/用户名枚举  
**风险:** 低危，仅能枚举用户名，不能直接获取敏感信息  
**投毒风险:** 0%  
**发现时间:** 2025-05-29  
**POC仓库:** [cve-2016-20012](https://github.com/aztec-eagle/cve-2016-20012)  

---

### [CVE-2025-5328](CVE-2025-5328-voyagken_CVE-2025-5328.md) 🟡 ✅

**名称:** CVE-2025-5328 – chshcms mccms 2.7 Path Traversal  
**类型:** 路径遍历  
**风险:** 中危，可能导致任意文件删除或覆盖  
**投毒风险:** 10%  
**发现时间:** 2025-05-29  
**POC仓库:** [CVE-2025-5328](https://github.com/voyagken/CVE-2025-5328)  

---

### [CVE-2025-48827](CVE-2025-48827-0xgh057r3c0n_CVE-2025-48827.md) 🔴 ✅

**名称:** CVE-2025-48827 vBulletin 未授权API控制器方法调用导致RCE  
**类型:** 远程代码执行  
**风险:** 高危，允许未经身份验证的攻击者执行任意代码  
**投毒风险:** 0%  
**发现时间:** 2025-05-29  
**POC仓库:** [CVE-2025-48827](https://github.com/0xgh057r3c0n/CVE-2025-48827)  

---

### [CVE-2025-46204](CVE-2025-46204-spbavarva_CVE-2025-46204.md) 🟡 ✅

**名称:** Unifiedtransform v2.X Incorrect Access Control  
**类型:** Incorrect Access Control  
**风险:** 中危，可能导致数据篡改和未授权访问  
**投毒风险:** 10%  
**发现时间:** 2025-05-29  
**POC仓库:** [CVE-2025-46204](https://github.com/spbavarva/CVE-2025-46204)  

---

### [CVE-2025-2760](CVE-2025-2760-korden-c_CVE-2025-2760.md) 🔴 ✅

**名称:** CVE-2025-2760 – GIMP XWD File Parsing Integer Overflow Remote Code Execution Vulnerability  
**类型:** 整数溢出导致远程代码执行  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 80%  
**发现时间:** 2025-05-29  
**POC仓库:** [CVE-2025-2760](https://github.com/korden-c/CVE-2025-2760)  

---

### [CVE-2025-47827](CVE-2025-47827-Zedeldi_CVE-2025-47827.md) 🔴 ✅

**名称:** CVE-2025-47827 - IGEL OS Secure Boot Bypass  
**类型:** 安全启动绕过  
**风险:** 高危，允许未经授权的代码执行和操作系统替换  
**投毒风险:** 10%  
**发现时间:** 2025-05-29  
**POC仓库:** [CVE-2025-47827](https://github.com/Zedeldi/CVE-2025-47827)  

---

### [CVE-2025-30208](CVE-2025-30208-nkuty_CVE-2025-30208-31125-31486-32395.md) 🟡 ✅

**名称:** CVE-2025-30208-Vite-任意文件读取  
**类型:** 任意文件读取  
**风险:** 中危，可能导致敏感信息泄露  
**投毒风险:** 1%  
**发现时间:** 2025-05-29  
**POC仓库:** [CVE-2025-30208-31125-31486-32395](https://github.com/nkuty/CVE-2025-30208-31125-31486-32395)  

---

### [CVE-2023-28293](CVE-2023-28293-CrazyDaveX86_CVE-2023-28293.md) 🔴 ✅

**名称:** CVE-2023-28293 - Windows Kernel Elevation of Privilege  
**类型:** 特权提升  
**风险:** 高危，允许低权限用户提升至SYSTEM权限  
**投毒风险:** 5%  
**发现时间:** 2025-05-29  
**POC仓库:** [CVE-2023-28293](https://github.com/CrazyDaveX86/CVE-2023-28293)  

---

### [CVE-2025-29927](CVE-2025-29927-SugiB3o_vulnerable-nextjs-14-CVE-2025-29927.md) 🔴 ✅

**名称:** CVE-2025-29927 Next.js Middleware 权限绕过  
**类型:** 权限绕过  
**风险:** 高危，可能导致未经授权的访问和数据泄露  
**投毒风险:** 0%  
**发现时间:** 2025-05-29  
**POC仓库:** [vulnerable-nextjs-14-CVE-2025-29927](https://github.com/SugiB3o/vulnerable-nextjs-14-CVE-2025-29927)  

---

### [CVE-2025-46203](CVE-2025-46203-spbavarva_CVE-2025-46203.md) 🟡 ✅

**名称:** Unifiedtransform v2.X Incorrect Access Control  
**类型:** Incorrect Access Control  
**风险:** 中危，可能导致未经授权的数据修改和权限提升  
**投毒风险:** 0%  
**发现时间:** 2025-05-29  
**POC仓库:** [CVE-2025-46203](https://github.com/spbavarva/CVE-2025-46203)  

---

### [CVE-2024-56903](CVE-2024-56903-DRAGOWN_CVE-2024-56903.md) 🔴 ✅

**名称:** CVE-2024-56903-Geovision GV-ASWeb-CSRF  
**类型:** 跨站请求伪造 (CSRF)  
**风险:** 高危，允许未授权用户执行敏感操作，例如账户管理  
**投毒风险:** 10%  
**发现时间:** 2025-05-29  
**POC仓库:** [CVE-2024-56903](https://github.com/DRAGOWN/CVE-2024-56903)  

---

### [CVE-2025-26263](CVE-2025-26263-DRAGOWN_CVE-2025-26263.md) 🟡 ✅

**名称:** CVE-2025-26263-GeoVision ASManager-Credentials Disclosure  
**类型:** 凭据泄露  
**风险:** 中危，可能导致未经授权的访问和控制  
**投毒风险:** 5%  
**发现时间:** 2025-05-29  
**POC仓库:** [CVE-2025-26263](https://github.com/DRAGOWN/CVE-2025-26263)  

---

### [CVE-2025-1461](CVE-2025-1461-neverendingsupport_nes-vuetify-cve-2025-1461.md) 🟡 ✅

**名称:** CVE-2025-1461-Vuetify-XSS  
**类型:** 跨站脚本 (XSS)  
**风险:** 中危，可能导致用户信息泄露和会话劫持  
**投毒风险:** 10%  
**发现时间:** 2025-05-29  
**POC仓库:** [nes-vuetify-cve-2025-1461](https://github.com/neverendingsupport/nes-vuetify-cve-2025-1461)  

---

### [CVE-2023-1234](CVE-2023-1234-Yuri08loveElaina_CVE-2023-1234.md)  ✅

**名称:** CVE-2023-1234-Chrome-Android-域名欺骗  
**类型:** 域名欺骗  
**风险:** 低危，可能导致用户访问恶意网站，泄露个人信息  
**投毒风险:** 10%  
**发现时间:** 2025-05-29  
**POC仓库:** [CVE-2023-1234](https://github.com/Yuri08loveElaina/CVE-2023-1234)  

---

### [CVE-2021-22911](CVE-2021-22911-optionalCTF_Rocket.Chat-Automated-Account-Takeover-RCE-CVE-2021-22911.md) 🔴 ✅

**名称:** CVE-2021-22911 - Rocket.Chat NoSQL 注入导致 RCE  
**类型:** NoSQL 注入  
**风险:** 高危，可能导致账户接管和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-05-29  
**POC仓库:** [Rocket.Chat-Automated-Account-Takeover-RCE-CVE-2021-22911](https://github.com/optionalCTF/Rocket.Chat-Automated-Account-Takeover-RCE-CVE-2021-22911)  

---

### [CVE-2021-22911](CVE-2021-22911-jayngng_CVE-2021-22911.md) 🔴 ✅

**名称:** CVE-2021-22911 - Rocket.Chat NoSQL注入导致RCE  
**类型:** NoSQL注入  
**风险:** 高危，可能导致远程代码执行和数据泄露  
**投毒风险:** 10%  
**发现时间:** 2025-05-29  
**POC仓库:** [CVE-2021-22911](https://github.com/jayngng/CVE-2021-22911)  

---

### [CVE-2021-22911](CVE-2021-22911-ChrisPritchard_CVE-2021-22911-rust.md) 🔴 ✅

**名称:** CVE-2021-22911-Rocket.Chat-NoSQL注入  
**类型:** NoSQL注入  
**风险:** 高危，可能导致RCE（远程代码执行）  
**投毒风险:** 10%  
**发现时间:** 2025-05-29  
**POC仓库:** [CVE-2021-22911-rust](https://github.com/ChrisPritchard/CVE-2021-22911-rust)  

---

### [CVE-2021-22911](CVE-2021-22911-MrDottt_CVE-2021-22911.md) 🔴 ✅

**名称:** CVE-2021-22911-Rocket.Chat-NoSQL注入  
**类型:** NoSQL注入  
**风险:** 高危，可能导致账户接管和远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-05-29  
**POC仓库:** [CVE-2021-22911](https://github.com/MrDottt/CVE-2021-22911)  

---

### [CVE-2021-22911](CVE-2021-22911-CsEnox_CVE-2021-22911.md) 🔴 ✅

**名称:** CVE-2021-22911-Rocket.Chat-NoSQL注入  
**类型:** NoSQL注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-05-29  
**POC仓库:** [CVE-2021-22911](https://github.com/CsEnox/CVE-2021-22911)  

---

### [CVE-2021-22911](CVE-2021-22911-overgrowncarrot1_CVE-2021-22911.md) 🔴 ✅

**名称:** CVE-2021-22911 Rocket.Chat NoSQL注入导致RCE  
**类型:** NoSQL注入  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-05-29  
**POC仓库:** [CVE-2021-22911](https://github.com/overgrowncarrot1/CVE-2021-22911)  

---

### [CVE-2021-22911](CVE-2021-22911-yoohhuu_Rocket-Chat-3.12.1-PoC-CVE-2021-22911-.md) 🔴 ✅

**名称:** CVE-2021-22911-Rocket.Chat-NoSQL注入  
**类型:** NoSQL注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-05-29  
**POC仓库:** [Rocket-Chat-3.12.1-PoC-CVE-2021-22911-](https://github.com/yoohhuu/Rocket-Chat-3.12.1-PoC-CVE-2021-22911-)  

---

### [CVE-2021-22911](CVE-2021-22911-octodi_CVE-2021-22911.md) 🔴 ✅

**名称:** CVE-2021-22911-Rocket.Chat-NoSQL注入导致RCE  
**类型:** NoSQL注入  
**风险:** 高危，未授权RCE  
**投毒风险:** 10%  
**发现时间:** 2025-05-29  
**POC仓库:** [CVE-2021-22911](https://github.com/octodi/CVE-2021-22911)  

---

### [CVE-2023-22527](CVE-2023-22527-C1ph3rX13_CVE-2023-22527.md) 🔴 ✅

**名称:** CVE-2023-22527 Atlassian Confluence 远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，未经身份验证的攻击者可实现远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-05-29  
**POC仓库:** [CVE-2023-22527](https://github.com/C1ph3rX13/CVE-2023-22527)  

---

### [CVE-2023-22527](CVE-2023-22527-Niuwoo_CVE-2023-22527.md) 🔴 ✅

**名称:** CVE-2023-22527-Atlassian Confluence-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，允许未授权的攻击者执行任意代码  
**投毒风险:** 0%  
**发现时间:** 2025-05-29  
**POC仓库:** [CVE-2023-22527](https://github.com/Niuwoo/CVE-2023-22527)  

---

### [CVE-2023-22527](CVE-2023-22527-MaanVader_CVE-2023-22527-POC.md) 🔴 ✅

**名称:** CVE-2023-22527-Atlassian Confluence-OGNL注入  
**类型:** OGNL注入  
**风险:** 高危，允许未经身份验证的攻击者执行远程代码  
**投毒风险:** 5%  
**发现时间:** 2025-05-29  
**POC仓库:** [CVE-2023-22527-POC](https://github.com/MaanVader/CVE-2023-22527-POC)  

---

### [CVE-2023-22527](CVE-2023-22527-adminlove520_CVE-2023-22527.md) 🔴 ✅

**名称:** CVE-2023-22527-Confluence-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，允许未经身份验证的攻击者执行任意代码  
**投毒风险:** 0%  
**发现时间:** 2025-05-29  
**POC仓库:** [CVE-2023-22527](https://github.com/adminlove520/CVE-2023-22527)  

---

### [CVE-2023-22527](CVE-2023-22527-ga0we1_CVE-2023-22527_Confluence_RCE.md) 🔴 ✅

**名称:** CVE-2023-22527 Confluence RCE  
**类型:** 远程代码执行(RCE)  
**风险:** 高危，允许未经身份验证的攻击者远程执行代码  
**投毒风险:** 0%  
**发现时间:** 2025-05-29  
**POC仓库:** [CVE-2023-22527_Confluence_RCE](https://github.com/ga0we1/CVE-2023-22527_Confluence_RCE)  

---

### [CVE-2023-22527](CVE-2023-22527-Sudistark_patch-diff-CVE-2023-22527.md) 🔴 ✅

**名称:** CVE-2023-22527-Atlassian Confluence-RCE  
**类型:** 模板注入/RCE  
**风险:** 高危，允许未授权的远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-05-29  
**POC仓库:** [patch-diff-CVE-2023-22527](https://github.com/Sudistark/patch-diff-CVE-2023-22527)  

---

### [CVE-2023-22527](CVE-2023-22527-Drun1baby_CVE-2023-22527.md) 🔴 ✅

**名称:** CVE-2023-22527-Atlassian Confluence-模板注入RCE  
**类型:** 模板注入RCE  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-05-29  
**POC仓库:** [CVE-2023-22527](https://github.com/Drun1baby/CVE-2023-22527)  

---

### [CVE-2023-22527](CVE-2023-22527-cleverg0d_CVE-2023-22527.md) 🔴 ✅

**名称:** CVE-2023-22527 - Confluence OGNL 注入 RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，未经身份验证的远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-05-29  
**POC仓库:** [CVE-2023-22527](https://github.com/cleverg0d/CVE-2023-22527)  

---

### [CVE-2023-22527](CVE-2023-22527-VNCERT-CC_CVE-2023-22527-confluence.md) 🔴 ✅

**名称:** CVE-2023-22527-Confluence-远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，允许未授权的攻击者执行任意代码。  
**投毒风险:** 10%  
**发现时间:** 2025-05-29  
**POC仓库:** [CVE-2023-22527-confluence](https://github.com/VNCERT-CC/CVE-2023-22527-confluence)  

---

### [CVE-2023-22527](CVE-2023-22527-Vozec_CVE-2023-22527.md)  ✅

**名称:** CVE-2023-22527-Confluence-远程代码执行  
**类型:** 远程代码执行  
**风险:** 严重，允许未经身份验证的攻击者执行任意代码  
**投毒风险:** 1%  
**发现时间:** 2025-05-29  
**POC仓库:** [CVE-2023-22527](https://github.com/Vozec/CVE-2023-22527)  

---

### [CVE-2023-22527](CVE-2023-22527-Avento_CVE-2023-22527_Confluence_RCE.md)  ✅

**名称:** CVE-2023-22527-Confluence-RCE  
**类型:** 远程代码执行  
**风险:** 严重，未经身份验证的攻击者可以实现远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-05-29  
**POC仓库:** [CVE-2023-22527_Confluence_RCE](https://github.com/Avento/CVE-2023-22527_Confluence_RCE)  

---

### [CVE-2023-22527](CVE-2023-22527-Chocapikk_CVE-2023-22527.md) 🔴 ✅

**名称:** CVE-2023-22527 - Atlassian Confluence 远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，允许未授权的攻击者执行任意代码。  
**投毒风险:** 10%  
**发现时间:** 2025-05-29  
**POC仓库:** [CVE-2023-22527](https://github.com/Chocapikk/CVE-2023-22527)  

---

### [CVE-2023-22527](CVE-2023-22527-Manh130902_CVE-2023-22527-POC.md) 🔴 ✅

**名称:** CVE-2023-22527 - Atlassian Confluence RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，允许未经身份验证的攻击者执行任意代码  
**投毒风险:** 0%  
**发现时间:** 2025-05-29  
**POC仓库:** [CVE-2023-22527-POC](https://github.com/Manh130902/CVE-2023-22527-POC)  

---

### [CVE-2023-22527](CVE-2023-22527-RevoltSecurities_CVE-2023-22527.md) 🔴 ✅

**名称:** CVE-2023-22527-Atlassian Confluence-OGNL注入  
**类型:** OGNL注入  
**风险:** 高危，允许未经身份验证的攻击者执行远程代码  
**投毒风险:** 20%  
**发现时间:** 2025-05-29  
**POC仓库:** [CVE-2023-22527](https://github.com/RevoltSecurities/CVE-2023-22527)  

---

### [CVE-2023-22527](CVE-2023-22527-Privia-Security_CVE-2023-22527.md) 🔴 ✅

**名称:** CVE-2023-22527 Atlassian Confluence OGNL注入 RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，允许未授权用户执行任意代码  
**投毒风险:** 20%  
**发现时间:** 2025-05-29  
**POC仓库:** [CVE-2023-22527](https://github.com/Privia-Security/CVE-2023-22527)  

---

### [CVE-2023-22527](CVE-2023-22527-thanhlam-attt_CVE-2023-22527.md) 🔴 ✅

**名称:** CVE-2023-22527-Atlassian Confluence-OGNL注入RCE  
**类型:** 远程代码执行(RCE)  
**风险:** 高危，允许未授权的攻击者执行任意代码  
**投毒风险:** 5%  
**发现时间:** 2025-05-29  
**POC仓库:** [CVE-2023-22527](https://github.com/thanhlam-attt/CVE-2023-22527)  

---

### [CVE-2023-22527](CVE-2023-22527-YongYe-Security_CVE-2023-22527.md) 🔴 ✅

**名称:** CVE-2023-22527-Confluence-远程代码执行  
**类型:** 模板注入/OGNL注入  
**风险:** 高危，允许未授权的远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-05-29  
**POC仓库:** [CVE-2023-22527](https://github.com/YongYe-Security/CVE-2023-22527)  

---

### [CVE-2023-22527](CVE-2023-22527-Boogipop_CVE-2023-22527-Godzilla-MEMSHELL.md) 🔴 ✅

**名称:** CVE-2023-22527-Confluence-RCE  
**类型:** 远程代码执行  
**风险:** 高危，未经身份验证的攻击者可以执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-05-29  
**POC仓库:** [CVE-2023-22527-Godzilla-MEMSHELL](https://github.com/Boogipop/CVE-2023-22527-Godzilla-MEMSHELL)  

---

### [CVE-2023-22527](CVE-2023-22527-yoryio_CVE-2023-22527.md) 🔴 ✅

**名称:** CVE-2023-22527 - Atlassian Confluence 远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，允许未授权的攻击者执行任意代码  
**投毒风险:** 1%  
**发现时间:** 2025-05-29  
**POC仓库:** [CVE-2023-22527](https://github.com/yoryio/CVE-2023-22527)  

---

### [CVE-2023-22527](CVE-2023-22527-M0untainShley_CVE-2023-22527-MEMSHELL.md) 🔴 ✅

**名称:** CVE-2023-22527-Confluence-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，未经身份验证的远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-05-29  
**POC仓库:** [CVE-2023-22527-MEMSHELL](https://github.com/M0untainShley/CVE-2023-22527-MEMSHELL)  

---

### [CVE-2023-22527](CVE-2023-22527-AxthonyV_CVE-2023-22527.md) 🔴 ✅

**名称:** CVE-2023-22527-Confluence-RCE  
**类型:** 远程代码执行(RCE)  
**风险:** 高危，未授权的远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-05-29  
**POC仓库:** [CVE-2023-22527](https://github.com/AxthonyV/CVE-2023-22527)  

---

### [CVE-2023-22527](CVE-2023-22527-kh4sh3i_CVE-2023-22527.md) 🔴 ✅

**名称:** CVE-2023-22527-Atlassian Confluence-RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，未授权远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-05-29  
**POC仓库:** [CVE-2023-22527](https://github.com/kh4sh3i/CVE-2023-22527)  

---

### [CVE-2023-22527](CVE-2023-22527-vulncheck-oss_cve-2023-22527.md) 🔴 ✅

**名称:** CVE-2023-22527-Atlassian Confluence-RCE  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 5%  
**发现时间:** 2025-05-29  
**POC仓库:** [cve-2023-22527](https://github.com/vulncheck-oss/cve-2023-22527)  

---

### [CVE-2023-22527](CVE-2023-22527-thompson005_CVE-2023-22527.md) 🔴 ✅

**名称:** CVE-2023-22527-Atlassian Confluence-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，允许未经身份验证的攻击者执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-05-29  
**POC仓库:** [CVE-2023-22527](https://github.com/thompson005/CVE-2023-22527)  

---

### [CVE-2025-29632](CVE-2025-29632-OHnogood_CVE-2025-29632.md) 🔴 ✅

**名称:** CVE-2025-29632 - free5gc AMF拒绝服务  
**类型:** 拒绝服务 (DoS)  
**风险:** 高危，导致5G网络AMF组件崩溃，影响用户连接  
**投毒风险:** 10%  
**发现时间:** 2025-05-29  
**POC仓库:** [CVE-2025-29632](https://github.com/OHnogood/CVE-2025-29632)  

---

### [CVE-2025-46078](CVE-2025-46078-yggcwhat_CVE-2025-46078.md) 🔴 ✅

**名称:** CVE-2025-46078-HuoCMS-任意文件写入  
**类型:** 任意文件写入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-05-29  
**POC仓库:** [CVE-2025-46078](https://github.com/yggcwhat/CVE-2025-46078)  

---

### [CVE-2025-46080](CVE-2025-46080-yggcwhat_CVE-2025-46080.md) 🔴 ✅

**名称:** HuoCMS <=V3.5.1 任意文件重命名导致任意代码执行漏洞  
**类型:** 任意文件重命名导致任意代码执行  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-05-29  
**POC仓库:** [CVE-2025-46080](https://github.com/yggcwhat/CVE-2025-46080)  

---

### [CVE-2023-46818](CVE-2023-46818-engranaabubakar_CVE-2023-46818.md) 🔴 ✅

**名称:** CVE-2023-46818-ISPConfig-PHP代码注入  
**类型:** PHP代码注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-05-28  
**POC仓库:** [CVE-2023-46818](https://github.com/engranaabubakar/CVE-2023-46818)  

---

### [CVE-2018-1160](CVE-2018-1160-sergiovks_CVE-2018-1160-Netatalk-OpenSession-Authentication-Bypass.md) 🔴 ✅

**名称:** CVE-2018-1160-Netatalk-OpenSession-远程代码执行  
**类型:** 越界写入 (Out-of-bounds Write)  
**风险:** 高危，允许未授权的远程攻击者执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-05-28  
**POC仓库:** [CVE-2018-1160-Netatalk-OpenSession-Authentication-Bypass](https://github.com/sergiovks/CVE-2018-1160-Netatalk-OpenSession-Authentication-Bypass)  

---

### [CVE-2018-8097](CVE-2018-8097-SilentVoid13_CVE-2018-8097.md) 🔴 ✅

**名称:** CVE-2018-8097-pyeve-代码注入  
**类型:** 代码注入  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-05-28  
**POC仓库:** [CVE-2018-8097](https://github.com/SilentVoid13/CVE-2018-8097)  

---

### [CVE-2018-8097](CVE-2018-8097-StellarDriftLabs_CVE-2018-8097.md) 🔴 ✅

**名称:** CVE-2018-8097 - Eve (pyeve) 代码注入  
**类型:** 代码注入  
**风险:** 高危，允许远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-05-28  
**POC仓库:** [CVE-2018-8097](https://github.com/StellarDriftLabs/CVE-2018-8097)  

---

### [CVE-2023-38600](CVE-2023-38600-afrojack1_cve202338600test.github.io.md) 🔴 ✅

**名称:** CVE-2023-38600 - Apple Safari Web Content Execution of Arbitrary Code  
**类型:** 代码执行  
**风险:** 高危，可能导致任意代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-05-28  
**POC仓库:** [cve202338600test.github.io](https://github.com/afrojack1/cve202338600test.github.io)  

---

### [CVE-2025-5287](CVE-2025-5287-Nxploited_CVE-2025-5287.md) 🔴 ✅

**名称:** CVE-2025-5287-Likes and Dislikes Plugin-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致敏感数据泄露  
**投毒风险:** 5%  
**发现时间:** 2025-05-28  
**POC仓库:** [CVE-2025-5287](https://github.com/Nxploited/CVE-2025-5287)  

---

### [CVE-2025-22252](CVE-2025-22252-korden-c_CVE-2025-22252.md)  ✅

**名称:** CVE-2025-22252 – Fortinet 产品认证绕过  
**类型:** 认证绕过  
**风险:** 严重，可完全控制受影响设备  
**投毒风险:** 80%  
**发现时间:** 2025-05-28  
**POC仓库:** [CVE-2025-22252](https://github.com/korden-c/CVE-2025-22252)  

---

### [CVE-2017-9248](CVE-2017-9248-capt-meelo_Telewreck.md) 🔴 ✅

**名称:** CVE-2017-9248 - Telerik UI for ASP.NET AJAX Cryptographic Weakness  
**类型:** 加密缺陷  
**风险:** 高危，可能导致MachineKey泄露，任意文件上传/下载，XSS，或ASP.NET ViewState 泄露，最终导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-05-28  
**POC仓库:** [Telewreck](https://github.com/capt-meelo/Telewreck)  

---

### [CVE-2017-9248](CVE-2017-9248-ictnamanh_CVE-2017-9248.md) 🔴 ✅

**名称:** CVE-2017-9248 - Telerik UI for ASP.NET AJAX Cryptographic Weakness  
**类型:** 加密缺陷  
**风险:** 高危，可能导致MachineKey泄露、任意文件上传/下载、XSS或ASP.NET ViewState compromise以及远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-05-28  
**POC仓库:** [CVE-2017-9248](https://github.com/ictnamanh/CVE-2017-9248)  

---

### [CVE-2017-9248](CVE-2017-9248-oldboysonnt_dp.md) 🔴 ✅

**名称:** CVE-2017-9248 - Telerik UI for ASP.NET AJAX Cryptographic Weakness  
**类型:** 密码学漏洞  
**风险:** 高危，可能导致MachineKey泄露、任意文件上传/下载、XSS或ASP.NET ViewState compromise。  
**投毒风险:** 2%  
**发现时间:** 2025-05-28  
**POC仓库:** [dp](https://github.com/oldboysonnt/dp)  

---

### [CVE-2017-9248](CVE-2017-9248-bao7uo_dp_crypto.md) 🔴 ✅

**名称:** CVE-2017-9248 - Telerik UI for ASP.NET AJAX Cryptographic Weakness  
**类型:** 加密算法缺陷  
**风险:** 高危，可能导致MachineKey泄露、任意文件上传/下载、XSS、ViewState篡改、远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-05-28  
**POC仓库:** [dp_crypto](https://github.com/bao7uo/dp_crypto)  

---

### [CVE-2017-9248](CVE-2017-9248-cehamod_UI_CVE-2017-9248.md) 🔴 ✅

**名称:** CVE-2017-9248 - Telerik UI for ASP.NET AJAX Cryptographic Weakness  
**类型:** 密码学漏洞/信息泄露/任意文件上传/XSS/ViewState Compromise  
**风险:** 高危，可能导致敏感信息泄露、远程代码执行、跨站脚本攻击  
**投毒风险:** 0%  
**发现时间:** 2025-05-28  
**POC仓库:** [UI_CVE-2017-9248](https://github.com/cehamod/UI_CVE-2017-9248)  

---

### [CVE-2017-9248](CVE-2017-9248-blacklanternsecurity_dp_cryptomg.md) 🔴 ✅

**名称:** CVE-2017-9248 - Telerik UI for ASP.NET AJAX 漏洞  
**类型:** 加密密钥泄露/远程代码执行/XSS/ViewState 泄露  
**风险:** 高危，可能导致敏感信息泄露和完全控制服务器  
**投毒风险:** 0%  
**发现时间:** 2025-05-28  
**POC仓库:** [dp_cryptomg](https://github.com/blacklanternsecurity/dp_cryptomg)  

---

### [CVE-2017-9248](CVE-2017-9248-0xsharz_telerik-scanner-cve-2017-9248.md) 🔴 ✅

**名称:** CVE-2017-9248 - Telerik UI for ASP.NET AJAX 漏洞  
**类型:** 加密弱点/远程代码执行 (RCE)  
**风险:** 高危，可能导致MachineKey泄露、任意文件上传/下载、XSS、ViewState泄露甚至远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-05-28  
**POC仓库:** [telerik-scanner-cve-2017-9248](https://github.com/0xsharz/telerik-scanner-cve-2017-9248)  

---

### [CVE-2024-28995](CVE-2024-28995-demoAlitalia_CVE-2024-28995.md) 🔴 ✅

**名称:** CVE-2024-28995-SolarWinds Serv-U-目录遍历  
**类型:** 目录遍历  
**风险:** 高危，可能导致敏感文件泄露  
**投毒风险:** 5%  
**发现时间:** 2025-05-28  
**POC仓库:** [CVE-2024-28995](https://github.com/demoAlitalia/CVE-2024-28995)  

---

### [CVE-2024-28995](CVE-2024-28995-ggfzx_CVE-2024-28995.md) 🔴 ✅

**名称:** CVE-2024-28995 - SolarWinds Serv-U 目录遍历  
**类型:** 目录遍历/路径穿越  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-05-28  
**POC仓库:** [CVE-2024-28995](https://github.com/ggfzx/CVE-2024-28995)  

---

### [CVE-2024-28995](CVE-2024-28995-huseyinstif_CVE-2024-28995-Nuclei-Template.md) 🔴 ✅

**名称:** CVE-2024-28995-SolarWinds Serv-U-目录遍历  
**类型:** 目录遍历  
**风险:** 高危，可能导致敏感文件泄露  
**投毒风险:** 0%  
**发现时间:** 2025-05-28  
**POC仓库:** [CVE-2024-28995-Nuclei-Template](https://github.com/huseyinstif/CVE-2024-28995-Nuclei-Template)  

---

### [CVE-2024-28995](CVE-2024-28995-0xc4t_CVE-2024-28995.md) 🔴 ✅

**名称:** CVE-2024-28995 - SolarWinds Serv-U 目录遍历漏洞  
**类型:** 目录遍历  
**风险:** 高危，可能导致敏感文件泄露  
**投毒风险:** 0%  
**发现时间:** 2025-05-28  
**POC仓库:** [CVE-2024-28995](https://github.com/0xc4t/CVE-2024-28995)  

---

### [CVE-2024-28995](CVE-2024-28995-muhammetali20_CVE-2024-28995.md) 🔴 ✅

**名称:** CVE-2024-28995 SolarWinds Serv-U 目录遍历漏洞  
**类型:** 目录遍历  
**风险:** 高危，可能导致敏感文件泄露  
**投毒风险:** 10%  
**发现时间:** 2025-05-28  
**POC仓库:** [CVE-2024-28995](https://github.com/muhammetali20/CVE-2024-28995)  

---

### [CVE-2024-28995](CVE-2024-28995-bigb0x_CVE-2024-28995.md) 🔴 ✅

**名称:** CVE-2024-28995 - SolarWinds Serv-U Directory Traversal  
**类型:** 目录遍历  
**风险:** 高危，可能导致敏感文件泄露  
**投毒风险:** 0%  
**发现时间:** 2025-05-28  
**POC仓库:** [CVE-2024-28995](https://github.com/bigb0x/CVE-2024-28995)  

---

### [CVE-2024-28995](CVE-2024-28995-Praison001_CVE-2024-28995-SolarWinds-Serv-U.md) 🔴 ✅

**名称:** CVE-2024-28995-SolarWinds-Serv-U 目录遍历  
**类型:** 目录遍历  
**风险:** 高危，允许未授权用户读取服务器上的敏感文件  
**投毒风险:** 0%  
**发现时间:** 2025-05-28  
**POC仓库:** [CVE-2024-28995-SolarWinds-Serv-U](https://github.com/Praison001/CVE-2024-28995-SolarWinds-Serv-U)  

---

### [CVE-2024-28995](CVE-2024-28995-Stuub_CVE-2024-28995.md) 🔴 ✅

**名称:** CVE-2024-28995-SolarWinds Serv-U 目录遍历  
**类型:** 目录遍历  
**风险:** 高危，可能导致敏感文件泄露  
**投毒风险:** 0%  
**发现时间:** 2025-05-28  
**POC仓库:** [CVE-2024-28995](https://github.com/Stuub/CVE-2024-28995)  

---

### [CVE-2024-28995](CVE-2024-28995-gotr00t0day_CVE-2024-28995.md) 🔴 ✅

**名称:** CVE-2024-28995 - SolarWinds Serv-U 目录遍历漏洞  
**类型:** 目录遍历  
**风险:** 高危，允许未经身份验证的远程攻击者读取主机上的敏感文件  
**投毒风险:** 0%  
**发现时间:** 2025-05-28  
**POC仓库:** [CVE-2024-28995](https://github.com/gotr00t0day/CVE-2024-28995)  

---

### [CVE-2024-28995](CVE-2024-28995-ibrahimsql_CVE-2024-28995.md) 🔴 ✅

**名称:** CVE-2024-28995 - SolarWinds Serv-U 目录遍历  
**类型:** 目录遍历  
**风险:** 高危，允许未授权访问服务器上的敏感文件  
**投毒风险:** 1%  
**发现时间:** 2025-05-28  
**POC仓库:** [CVE-2024-28995](https://github.com/ibrahimsql/CVE-2024-28995)  

---

### [CVE-2025-2539](CVE-2025-2539-verylazytech_CVE-2025-2539.md) 🔴 ✅

**名称:** CVE-2025-2539 - File Away <= 3.9.9.0.1 - Unauthenticated Arbitrary File Read  
**类型:** 任意文件读取  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-05-28  
**POC仓库:** [CVE-2025-2539](https://github.com/verylazytech/CVE-2025-2539)  

---

### [CVE-2024-32462](CVE-2024-32462-SpiralBL0CK_CVE-2024-32462.md) 🔴 ✅

**名称:** CVE-2024-32462-Flatpak-SandboxEscape  
**类型:** 沙箱逃逸  
**风险:** 高危，可能导致沙箱逃逸，在宿主机上执行任意代码  
**投毒风险:** 0%  
**发现时间:** 2025-05-28  
**POC仓库:** [CVE-2024-32462](https://github.com/SpiralBL0CK/CVE-2024-32462)  

---

### [CVE-2021-41773](CVE-2021-41773-Ask-os_CVE-2021-41773.md) 🔴 ✅

**名称:** CVE-2021-41773 - Apache HTTP Server Path Traversal 和 RCE  
**类型:** 路径遍历/远程代码执行  
**风险:** 高危，可能导致文件泄露和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-05-28  
**POC仓库:** [CVE-2021-41773](https://github.com/Ask-os/CVE-2021-41773)  

---

### [CVE-2025-24071](CVE-2025-24071-ex-cal1bur_SMB_CVE-2025-24071.md) 🟡 ✅

**名称:** CVE-2025-24071 Windows File Explorer Spoofing Vulnerability  
**类型:** 信息泄露  
**风险:** 中危，泄露NTLM hash可能导致权限提升  
**投毒风险:** 0%  
**发现时间:** 2025-05-28  
**POC仓库:** [SMB_CVE-2025-24071](https://github.com/ex-cal1bur/SMB_CVE-2025-24071)  

---

### [CVE-2025-1661](CVE-2025-1661-exploit-machine_PoC-EXPLOIT-CVE-2025-1661-Critical-Vulnerability-in-HUSKY-WooCommerce-Filter-Plugin.md) 🔴 ✅

**名称:** CVE-2025-1661-HUSKY WooCommerce Filter Plugin-LFI  
**类型:** 本地文件包含 (LFI)  
**风险:** 高危，可能导致敏感数据泄露和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-05-27  
**POC仓库:** [PoC-EXPLOIT-CVE-2025-1661-Critical-Vulnerability-in-HUSKY-WooCommerce-Filter-Plugin](https://github.com/exploit-machine/PoC-EXPLOIT-CVE-2025-1661-Critical-Vulnerability-in-HUSKY-WooCommerce-Filter-Plugin)  

---

### [CVE-2024-55656](CVE-2024-55656-rick2600_redis-stack-CVE-2024-55656.md) 🔴 ✅

**名称:** CVE-2024-55656 - RedisBloom Integer Overflow Remote Code Execution Vulnerability  
**类型:** Integer Overflow  
**风险:** 高危，可能导致信息泄露和OOB写入，最终可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-05-27  
**POC仓库:** [redis-stack-CVE-2024-55656](https://github.com/rick2600/redis-stack-CVE-2024-55656)  

---

### [CVE-2025-32013](CVE-2025-32013-exploit-machine_PoC-EXPLOIT-CVE-2025-32013-SSRF-in-LNbits-Lightning-Network-Payment-System.md) 🔴 ✅

**名称:** CVE-2025-32013-LNbits-SSRF  
**类型:** SSRF  
**风险:** 高危，可能导致内部资源泄露和权限提升  
**投毒风险:** 20%  
**发现时间:** 2025-05-27  
**POC仓库:** [PoC-EXPLOIT-CVE-2025-32013-SSRF-in-LNbits-Lightning-Network-Payment-System](https://github.com/exploit-machine/PoC-EXPLOIT-CVE-2025-32013-SSRF-in-LNbits-Lightning-Network-Payment-System)  

---

### [CVE-2023-5044](CVE-2023-5044-4ARMED_cve-2023-5044.md) 🔴 ✅

**名称:** CVE-2023-5044-ingress-nginx-代码注入  
**类型:** 代码注入  
**风险:** 高危，可能导致权限提升和集群控制  
**投毒风险:** 10%  
**发现时间:** 2025-05-27  
**POC仓库:** [cve-2023-5044](https://github.com/4ARMED/cve-2023-5044)  

---

### [CVE-2024-4577](CVE-2024-4577-KimJuhyeong95_cve-2024-4577.md) 🔴 ✅

**名称:** CVE-2024-4577 - PHP-CGI 参数注入导致RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 5%  
**发现时间:** 2025-05-27  
**POC仓库:** [cve-2024-4577](https://github.com/KimJuhyeong95/cve-2024-4577)  

---

### [CVE-2023-5044](CVE-2023-5044-r0binak_CVE-2023-5044.md) 🔴 ✅

**名称:** CVE-2023-5044 - Kubernetes Ingress Nginx Code Injection  
**类型:** 代码注入  
**风险:** 高危，可能导致集群接管和敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-05-27  
**POC仓库:** [CVE-2023-5044](https://github.com/r0binak/CVE-2023-5044)  

---

### [CVE-2023-5044](CVE-2023-5044-KubernetesBachelor_CVE-2023-5044.md) 🔴 ✅

**名称:** CVE-2023-5044-ingress-nginx-代码注入  
**类型:** 代码注入  
**风险:** 高危，可能导致集群权限提升，敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-05-27  
**POC仓库:** [CVE-2023-5044](https://github.com/KubernetesBachelor/CVE-2023-5044)  

---

### [CVE-2024-21626](CVE-2024-21626-zpxlz_CVE-2024-21626-POC.md) 🔴 ✅

**名称:** CVE-2024-21626-runc容器逃逸  
**类型:** 容器逃逸  
**风险:** 高危，可完全控制宿主机  
**投毒风险:** 0%  
**发现时间:** 2025-05-27  
**POC仓库:** [CVE-2024-21626-POC](https://github.com/zpxlz/CVE-2024-21626-POC)  

---

### [CVE-2024-21626](CVE-2024-21626-cdxiaodong_CVE-2024-21626.md) 🔴 ✅

**名称:** CVE-2024-21626-runc容器逃逸  
**类型:** 容器逃逸  
**风险:** 高危，可能导致宿主机权限泄露和完全控制  
**投毒风险:** 5%  
**发现时间:** 2025-05-27  
**POC仓库:** [CVE-2024-21626](https://github.com/cdxiaodong/CVE-2024-21626)  

---

### [CVE-2024-21626](CVE-2024-21626-Wall1e_CVE-2024-21626-POC.md) 🔴 ✅

**名称:** CVE-2024-21626-runc容器逃逸  
**类型:** 容器逃逸  
**风险:** 高危，可能导致主机控制  
**投毒风险:** 10%  
**发现时间:** 2025-05-27  
**POC仓库:** [CVE-2024-21626-POC](https://github.com/Wall1e/CVE-2024-21626-POC)  

---

### [CVE-2024-21626](CVE-2024-21626-zhangguanzhang_CVE-2024-21626.md) 🔴 ✅

**名称:** CVE-2024-21626 - runc 容器逃逸漏洞  
**类型:** 容器逃逸  
**风险:** 高危，可能导致主机文件系统访问、权限提升  
**投毒风险:** 5%  
**发现时间:** 2025-05-27  
**POC仓库:** [CVE-2024-21626](https://github.com/zhangguanzhang/CVE-2024-21626)  

---

### [CVE-2024-21626](CVE-2024-21626-laysakura_CVE-2024-21626-demo.md) 🔴 ✅

**名称:** CVE-2024-21626-runc容器逃逸  
**类型:** 容器逃逸  
**风险:** 高危，允许攻击者逃逸容器并在主机上执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-05-27  
**POC仓库:** [CVE-2024-21626-demo](https://github.com/laysakura/CVE-2024-21626-demo)  

---

### [CVE-2024-21626](CVE-2024-21626-V0WKeep3r_CVE-2024-21626-runcPOC.md) 🔴 ✅

**名称:** CVE-2024-21626-runc容器逃逸  
**类型:** 容器逃逸  
**风险:** 高危，可能导致容器逃逸，完全控制宿主机  
**投毒风险:** 10%  
**发现时间:** 2025-05-27  
**POC仓库:** [CVE-2024-21626-runcPOC](https://github.com/V0WKeep3r/CVE-2024-21626-runcPOC)  

---

### [CVE-2024-21626](CVE-2024-21626-NitroCao_CVE-2024-21626.md) 🔴 ✅

**名称:** CVE-2024-21626-runc-container-breakout  
**类型:** 容器逃逸  
**风险:** 高危，可能导致主机完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-05-27  
**POC仓库:** [CVE-2024-21626](https://github.com/NitroCao/CVE-2024-21626)  

---

### [CVE-2024-21626](CVE-2024-21626-dorser_cve-2024-21626.md) 🔴 ✅

**名称:** CVE-2024-21626-runc容器逃逸  
**类型:** 容器逃逸  
**风险:** 高危，可导致容器逃逸，控制宿主机  
**投毒风险:** 0%  
**发现时间:** 2025-05-27  
**POC仓库:** [cve-2024-21626](https://github.com/dorser/cve-2024-21626)  

---

### [CVE-2024-21626](CVE-2024-21626-abian2_CVE-2024-21626.md) 🔴 ✅

**名称:** CVE-2024-21626-runc容器逃逸  
**类型:** 容器逃逸  
**风险:** 高危，可能导致容器逃逸，控制宿主机  
**投毒风险:** 10%  
**发现时间:** 2025-05-27  
**POC仓库:** [CVE-2024-21626](https://github.com/abian2/CVE-2024-21626)  

---

### [CVE-2024-21626](CVE-2024-21626-FlojBoj_CVE-2024-21626.md) 🔴 ✅

**名称:** CVE-2024-21626-runc-容器逃逸  
**类型:** 容器逃逸  
**风险:** 高危，可能导致主机文件系统访问和控制  
**投毒风险:** 5%  
**发现时间:** 2025-05-27  
**POC仓库:** [CVE-2024-21626](https://github.com/FlojBoj/CVE-2024-21626)  

---

### [CVE-2024-21626](CVE-2024-21626-Sk3pper_CVE-2024-21626-old-docker-versions.md) 🔴 ✅

**名称:** CVE-2024-21626 - runc 容器逃逸漏洞  
**类型:** 容器逃逸  
**风险:** 高危，可能导致完全的容器逃逸，控制宿主机  
**投毒风险:** 10%  
**发现时间:** 2025-05-27  
**POC仓库:** [CVE-2024-21626-old-docker-versions](https://github.com/Sk3pper/CVE-2024-21626-old-docker-versions)  

---

### [CVE-2024-21626](CVE-2024-21626-Sk3pper_CVE-2024-21626.md) 🔴 ✅

**名称:** CVE-2024-21626-runc容器逃逸  
**类型:** 容器逃逸  
**风险:** 高危，可导致完全的容器逃逸，控制宿主机  
**投毒风险:** 20%  
**发现时间:** 2025-05-27  
**POC仓库:** [CVE-2024-21626](https://github.com/Sk3pper/CVE-2024-21626)  

---

### [CVE-2024-21626](CVE-2024-21626-adaammmeeee_little-joke.md) 🔴 ✅

**名称:** CVE-2024-21626-runc-容器逃逸  
**类型:** 容器逃逸  
**风险:** 高危，可能导致主机文件系统访问和控制  
**投毒风险:** 10%  
**发现时间:** 2025-05-27  
**POC仓库:** [little-joke](https://github.com/adaammmeeee/little-joke)  

---

### [CVE-2024-21626](CVE-2024-21626-KubernetesBachelor_CVE-2024-21626.md) 🔴 ✅

**名称:** CVE-2024-21626-runc容器逃逸  
**类型:** 容器逃逸  
**风险:** 高危，可能导致主机被完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-05-27  
**POC仓库:** [CVE-2024-21626](https://github.com/KubernetesBachelor/CVE-2024-21626)  

---

### [CVE-2025-24071](CVE-2025-24071-LOOKY243_CVE-2025-24071-PoC.md) 🔴 

**名称:** CVE-2025-24071-Windows File Explorer Spoofing Vulnerability  
**类型:** 信息泄露/欺骗 (Spoofing)  
**风险:** 高危，可能导致NTLM凭据泄露和网络欺骗  
**投毒风险:** 10%  
**发现时间:** 2025-05-27  
**POC仓库:** [CVE-2025-24071-PoC](https://github.com/LOOKY243/CVE-2025-24071-PoC)  

---

### [CVE-2023-40130](CVE-2023-40130-wrlu_CVE-2023-40130.md) 🔴 ✅

**名称:** CVE-2023-40130-Android-权限提升  
**类型:** 权限提升  
**风险:** 高危，可能导致本地权限提升和后台活动启动  
**投毒风险:** 10%  
**发现时间:** 2025-05-27  
**POC仓库:** [CVE-2023-40130](https://github.com/wrlu/CVE-2023-40130)  

---

### [CVE-2024-8682](CVE-2024-8682-4minx_CVE-2024-8682.md) 🟡 ✅

**名称:** CVE-2024-8682 - JNews WordPress Theme Unauthorized User Registration  
**类型:** 未授权用户注册  
**风险:** 中危，可能允许未经授权的用户访问系统  
**投毒风险:** 0%  
**发现时间:** 2025-05-27  
**POC仓库:** [CVE-2024-8682](https://github.com/4minx/CVE-2024-8682)  

---

### [CVE-2025-3248](CVE-2025-3248-Vip3rLi0n_CVE-2025-3248.md) 🔴 ✅

**名称:** CVE-2025-3248-Langflow-代码注入  
**类型:** 代码注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-05-27  
**POC仓库:** [CVE-2025-3248](https://github.com/Vip3rLi0n/CVE-2025-3248)  

---

### [CVE-2020-14008](CVE-2020-14008-JackHars_cve-2020-14008.md) 🔴 ✅

**名称:** CVE-2020-14008 Zoho ManageEngine Applications Manager RCE  
**类型:** 远程代码执行  
**风险:** 高危，允许经过身份验证的管理员用户上传恶意JAR文件，从而导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-05-26  
**POC仓库:** [cve-2020-14008](https://github.com/JackHars/cve-2020-14008)  

---

### [CVE-2024-38014](CVE-2024-38014-Naman2701B_CVE-2024-38014.md) 🔴 ✅

**名称:** CVE-2024-38014 Windows Installer 特权提升漏洞  
**类型:** 特权提升  
**风险:** 高危，可能导致本地用户获取SYSTEM权限  
**投毒风险:** 5%  
**发现时间:** 2025-05-26  
**POC仓库:** [CVE-2024-38014](https://github.com/Naman2701B/CVE-2024-38014)  

---

### [CVE-2024-38014](CVE-2024-38014-Naman2701B_DLL-for-2024-38014.md) 🔴 ✅

**名称:** CVE-2024-38014-Windows Installer Elevation of Privilege  
**类型:** 权限提升  
**风险:** 高危，攻击者可以利用此漏洞获取SYSTEM权限  
**投毒风险:** 10%  
**发现时间:** 2025-05-26  
**POC仓库:** [DLL-for-2024-38014](https://github.com/Naman2701B/DLL-for-2024-38014)  

---

### [CVE-2025-4389](CVE-2025-4389-Yucaerin_CVE-2025-4389.md) 🔴 ✅

**名称:** CVE-2025-4389-Crawlomatic Multipage Scraper Post Generator-任意文件上传  
**类型:** 任意文件上传  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-05-26  
**POC仓库:** [CVE-2025-4389](https://github.com/Yucaerin/CVE-2025-4389)  

---

### [CVE-2025-32421](CVE-2025-32421-zeroc00I_CVE-2025-32421.md) 🟡 ✅

**名称:** CVE-2025-32421-Next.js-缓存投毒  
**类型:** 缓存投毒  
**风险:** 中危，可能导致敏感信息泄露或页面内容篡改  
**投毒风险:** 0%  
**发现时间:** 2025-05-26  
**POC仓库:** [CVE-2025-32421](https://github.com/zeroc00I/CVE-2025-32421)  

---

### [CVE-2025-4664](CVE-2025-4664-Leviticus-Triage_ChromSploit-Framework.md) 🟡 ✅

**名称:** CVE-2025-4664-Google Chrome-跨域数据泄露  
**类型:** 跨域数据泄露  
**风险:** 中危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-05-26  
**POC仓库:** [ChromSploit-Framework](https://github.com/Leviticus-Triage/ChromSploit-Framework)  

---

### [CVE-2024-55591](CVE-2024-55591-UMChacker_CVE-2024-55591-POC.md) 🔴 ✅

**名称:** CVE-2024-55591 – FortiOS WebSocket CLI 身份验证绕过  
**类型:** 身份验证绕过  
**风险:** 高危，攻击者可能获得超级管理员权限  
**投毒风险:** 10%  
**发现时间:** 2025-05-26  
**POC仓库:** [CVE-2024-55591-POC](https://github.com/UMChacker/CVE-2024-55591-POC)  

---

### [CVE-2025-46173](CVE-2025-46173-pruthuraut_CVE-2025-46173.md) 🔴 ✅

**名称:** CVE-2025-46173 - Online Exam Mastering System 1.0 存储型XSS  
**类型:** 存储型跨站脚本 (XSS)  
**风险:** 高危，可能导致管理员会话劫持和权限提升  
**投毒风险:** 10%  
**发现时间:** 2025-05-26  
**POC仓库:** [CVE-2025-46173](https://github.com/pruthuraut/CVE-2025-46173)  

---

### [CVE-2025-29927](CVE-2025-29927-sagsooz_CVE-2025-29927.md) 🔴 ✅

**名称:** CVE-2025-29927-Next.js Middleware Authorization Bypass  
**类型:** 权限绕过  
**风险:** 高危，可能导致未授权访问和数据泄露  
**投毒风险:** 10%  
**发现时间:** 2025-05-26  
**POC仓库:** [CVE-2025-29927](https://github.com/sagsooz/CVE-2025-29927)  

---

### [CVE-2025-27363](CVE-2025-27363-ov3rf1ow_CVE-2025-27363.md) 🔴 ✅

**名称:** CVE-2025-27363-FreeType-OOB写入  
**类型:** OOB写入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-05-26  
**POC仓库:** [CVE-2025-27363](https://github.com/ov3rf1ow/CVE-2025-27363)  

---

### [CVE-2025-2907](CVE-2025-2907-Yucaerin_CVE-2025-2907.md) 🔴 ✅

**名称:** CVE-2025-2907-Order Delivery Date Pro for WooCommerce-未授权任意选项更新  
**类型:** 未授权任意选项更新/CSRF  
**风险:** 高危，可能导致权限提升和网站控制  
**投毒风险:** 1%  
**发现时间:** 2025-05-26  
**POC仓库:** [CVE-2025-2907](https://github.com/Yucaerin/CVE-2025-2907)  

---

### [CVE-2025-24071](CVE-2025-24071-f4dee-backup_CVE-2025-24071.md) 🟡 ✅

**名称:** CVE-2025-24071 - Windows File Explorer Spoofing Vulnerability  
**类型:** 信息泄露/NTLM劫持  
**风险:** 中危，可能导致敏感信息泄露和身份冒用  
**投毒风险:** 5%  
**发现时间:** 2025-05-26  
**POC仓库:** [CVE-2025-24071](https://github.com/f4dee-backup/CVE-2025-24071)  

---

### [CVE-2024-42008](CVE-2024-42008-Foxer131_CVE-2024-42008-9-exploit.md) 🔴 ✅

**名称:** CVE-2024-42008-Roundcube-XSS  
**类型:** 跨站脚本攻击 (XSS)  
**风险:** 高危，允许远程攻击者窃取和发送受害者的电子邮件  
**投毒风险:** 10%  
**发现时间:** 2025-05-26  
**POC仓库:** [CVE-2024-42008-9-exploit](https://github.com/Foxer131/CVE-2024-42008-9-exploit)  

---

### [CVE-2020-11097](CVE-2020-11097-SpiralBL0CK_CVE-2020-11097-POC.md) 🟡 ✅

**名称:** CVE-2020-11097-FreeRDP-OOB读取  
**类型:** OOB读取  
**风险:** 中危，可能导致信息泄露或程序崩溃  
**投毒风险:** 0%  
**发现时间:** 2025-05-26  
**POC仓库:** [CVE-2020-11097-POC](https://github.com/SpiralBL0CK/CVE-2020-11097-POC)  

---

### [CVE-2025-22457](CVE-2025-22457-TRone-ux_CVE-2025-22457.md) 🔴 ✅

**名称:** CVE-2025-22457-Ivanti Connect Secure-栈溢出  
**类型:** 栈溢出  
**风险:** 高危，远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-05-25  
**POC仓库:** [CVE-2025-22457](https://github.com/TRone-ux/CVE-2025-22457)  

---

### [CVE-2020-24913](CVE-2020-24913-shpaw415_CVE-2020-24913-exploit.md) 🔴 ✅

**名称:** CVE-2020-24913-QCubed-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据库信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-05-25  
**POC仓库:** [CVE-2020-24913-exploit](https://github.com/shpaw415/CVE-2020-24913-exploit)  

---

### [CVE-2025-4322](CVE-2025-4322-darkDev-kirosky_CVE-2025-4322.md)  ✅

**名称:** CVE-2025-4322 - Motors WordPress Theme - Unauthenticated Privilege Escalation  
**类型:** 权限提升  
**风险:** 严重，允许未授权用户接管管理员账户  
**投毒风险:** 10%  
**发现时间:** 2025-05-25  
**POC仓库:** [CVE-2025-4322](https://github.com/darkDev-kirosky/CVE-2025-4322)  

---

### [CVE-2022-1388](CVE-2022-1388-PsychoSec2_CVE-2022-1388-POC.md) 🔴 ✅

**名称:** CVE-2022-1388 - F5 BIG-IP iControl REST 认证绕过远程代码执行  
**类型:** 认证绕过/远程代码执行  
**风险:** 高危，未授权远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-05-25  
**POC仓库:** [CVE-2022-1388-POC](https://github.com/PsychoSec2/CVE-2022-1388-POC)  

---

### [CVE-2025-4664](CVE-2025-4664-speinador_CVE-2025-4664-.md) 🟡 ✅

**名称:** CVE-2025-4664 - Google Chrome 跨域数据泄露  
**类型:** 跨域数据泄露  
**风险:** 中危，可能导致敏感信息泄露  
**投毒风险:** 5%  
**发现时间:** 2025-05-25  
**POC仓库:** [CVE-2025-4664-](https://github.com/speinador/CVE-2025-4664-)  

---

### [CVE-2024-0204](CVE-2024-0204-horizon3ai_CVE-2024-0204.md)  ✅

**名称:** CVE-2024-0204 GoAnywhere MFT 身份验证绕过  
**类型:** 身份验证绕过  
**风险:** 严重，可导致完全控制系统  
**投毒风险:** 1%  
**发现时间:** 2025-05-25  
**POC仓库:** [CVE-2024-0204](https://github.com/horizon3ai/CVE-2024-0204)  

---

### [CVE-2024-0204](CVE-2024-0204-cbeek-r7_CVE-2024-0204.md) 🔴 ✅

**名称:** CVE-2024-0204 - GoAnywhere MFT Authentication Bypass  
**类型:** 身份验证绕过  
**风险:** 高危，未经授权的攻击者可以创建管理员用户，从而完全控制系统  
**投毒风险:** 0%  
**发现时间:** 2025-05-25  
**POC仓库:** [CVE-2024-0204](https://github.com/cbeek-r7/CVE-2024-0204)  

---

### [CVE-2024-0204](CVE-2024-0204-m-cetin_CVE-2024-0204.md) 🔴 ✅

**名称:** CVE-2024-0204 GoAnywhere MFT Authentication Bypass  
**类型:** Authentication Bypass  
**风险:** Critical，未经授权的用户可以创建管理员用户，完全控制系统  
**投毒风险:** 5%  
**发现时间:** 2025-05-25  
**POC仓库:** [CVE-2024-0204](https://github.com/m-cetin/CVE-2024-0204)  

---

### [CVE-2024-0204](CVE-2024-0204-adminlove520_CVE-2024-0204.md) 🔴 ✅

**名称:** CVE-2024-0204 GoAnywhere MFT Authentication Bypass  
**类型:** Authentication Bypass  
**风险:** 高危，允许未授权用户创建管理员账户，从而完全控制系统。  
**投毒风险:** 0%  
**发现时间:** 2025-05-25  
**POC仓库:** [CVE-2024-0204](https://github.com/adminlove520/CVE-2024-0204)  

---

### [CVE-2024-0204](CVE-2024-0204-ibrahimsql_CVE-2024-0204.md) 🔴 ✅

**名称:** CVE-2024-0204-GoAnywhere MFT-身份验证绕过  
**类型:** 身份验证绕过  
**风险:** 高危，允许未经授权的用户创建管理员帐户，可能导致完全控制系统  
**投毒风险:** 10%  
**发现时间:** 2025-05-25  
**POC仓库:** [CVE-2024-0204](https://github.com/ibrahimsql/CVE-2024-0204)  

---

### [CVE-2020-13398](CVE-2020-13398-SpiralBL0CK_PoC-crash-CVE-2020-13398-.md) 🔴 ✅

**名称:** CVE-2020-13398-FreeRDP-OOB写入  
**类型:** OOB写入  
**风险:** 高危，可能导致拒绝服务或远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-05-25  
**POC仓库:** [PoC-crash-CVE-2020-13398-](https://github.com/SpiralBL0CK/PoC-crash-CVE-2020-13398-)  

---

### [CVE-2025-4664](CVE-2025-4664-korden-c_CVE-2025-4664.md) 🔴 ✅

**名称:** CVE-2025-4664 – Chrome Loader Referrer Policy Bypass  
**类型:** 跨域信息泄露/远程代码执行  
**风险:** 高危，可能导致敏感信息泄露和远程代码执行  
**投毒风险:** 60%  
**发现时间:** 2025-05-25  
**POC仓库:** [CVE-2025-4664](https://github.com/korden-c/CVE-2025-4664)  

---

### [CVE-2025-24813](CVE-2025-24813-mbanyamer_Apache-Tomcat---Remote-Code-Execution-via-Session-Deserialization-CVE-2025-24813-.md) 🔴 ✅

**名称:** CVE-2025-24813-Apache Tomcat-RCE  
**类型:** 远程代码执行  
**风险:** 高危，可完全控制服务器  
**投毒风险:** 0%  
**发现时间:** 2025-05-25  
**POC仓库:** [Apache-Tomcat---Remote-Code-Execution-via-Session-Deserialization-CVE-2025-24813-](https://github.com/mbanyamer/Apache-Tomcat---Remote-Code-Execution-via-Session-Deserialization-CVE-2025-24813-)  

---

### [CVE-2025-48708](CVE-2025-48708-B1tBreaker_CVE-2025-48708.md) 🟡 ✅

**名称:** CVE-2025-48708-Ghostscript-密码泄露  
**类型:** 敏感信息泄露  
**风险:** 中危，可能导致PDF文件密码泄露  
**投毒风险:** 0%  
**发现时间:** 2025-05-25  
**POC仓库:** [CVE-2025-48708](https://github.com/B1tBreaker/CVE-2025-48708)  

---

### [CVE-2025-0868](CVE-2025-0868-aidana-gift_CVE-2025-0868.md) 🔴 ✅

**名称:** CVE-2025-0868-DocsGPT-远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-05-25  
**POC仓库:** [CVE-2025-0868](https://github.com/aidana-gift/CVE-2025-0868)  

---

### [CVE-2025-36535](CVE-2025-36535-korden-c_CVE-2025-36535.md) 🔴 ✅

**名称:** CVE-2025-36535 – AutomationDirect MB-Gateway Unauthenticated Remote Access  
**类型:** 未授权远程访问  
**风险:** 高危，可能导致配置更改、运营中断或任意代码执行  
**投毒风险:** 20%  
**发现时间:** 2025-05-25  
**POC仓库:** [CVE-2025-36535](https://github.com/korden-c/CVE-2025-36535)  

---

### [CVE-2024-42009](CVE-2024-42009-0xbassiouny1337_CVE-2024-42009.md) 🔴 ✅

**名称:** CVE-2024-42009-Roundcube-XSS  
**类型:** 存储型XSS  
**风险:** 高危，可能导致邮件窃取、会话劫持、恶意代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-05-24  
**POC仓库:** [CVE-2024-42009](https://github.com/0xbassiouny1337/CVE-2024-42009)  

---

### [CVE-2024-42009](CVE-2024-42009-Bhanunamikaze_CVE-2024-42009.md) 🔴 ✅

**名称:** CVE-2024-42009-Roundcube-XSS  
**类型:** XSS  
**风险:** 高危，可能导致信息泄露、账户劫持和邮件窃取  
**投毒风险:** 10%  
**发现时间:** 2025-05-24  
**POC仓库:** [CVE-2024-42009](https://github.com/Bhanunamikaze/CVE-2024-42009)  

---

### [CVE-2024-42009](CVE-2024-42009-DaniTheHack3r_CVE-2024-42009-PoC.md) 🔴 ✅

**名称:** CVE-2024-42009-Roundcube-XSS邮件内容泄露  
**类型:** 跨站脚本 (XSS)  
**风险:** 高危，允许攻击者窃取邮件内容并可能接管用户浏览器  
**投毒风险:** 5%  
**发现时间:** 2025-05-24  
**POC仓库:** [CVE-2024-42009-PoC](https://github.com/DaniTheHack3r/CVE-2024-42009-PoC)  

---

### [CVE-2023-50564](CVE-2023-50564-Rai2en_CVE-2023-50564_Pluck-v4.7.18_PoC.md) 🔴 ✅

**名称:** CVE-2023-50564 Pluck-CMS v4.7.18 任意文件上传  
**类型:** 任意文件上传  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-05-24  
**POC仓库:** [CVE-2023-50564_Pluck-v4.7.18_PoC](https://github.com/Rai2en/CVE-2023-50564_Pluck-v4.7.18_PoC)  

---

### [CVE-2023-50564](CVE-2023-50564-ipuig_CVE-2023-50564.md) 🔴 ✅

**名称:** CVE-2023-50564-Pluck-CMS-任意文件上传  
**类型:** 任意文件上传  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-05-24  
**POC仓库:** [CVE-2023-50564](https://github.com/ipuig/CVE-2023-50564)  

---

### [CVE-2023-50564](CVE-2023-50564-thefizzyfish_CVE-2023-50564-pluck.md) 🔴 ✅

**名称:** CVE-2023-50564-Pluck-CMS-任意文件上传  
**类型:** 任意文件上传  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-05-24  
**POC仓库:** [CVE-2023-50564-pluck](https://github.com/thefizzyfish/CVE-2023-50564-pluck)  

---

### [CVE-2023-50564](CVE-2023-50564-rwexecute_CVE-2023-50564.md) 🔴 ✅

**名称:** CVE-2023-50564-Pluck-CMS-任意文件上传  
**类型:** 任意文件上传  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-05-24  
**POC仓库:** [CVE-2023-50564](https://github.com/rwexecute/CVE-2023-50564)  

---

### [CVE-2023-50564](CVE-2023-50564-Mrterrestrial_CVE-2023-50564.md) 🔴 ✅

**名称:** CVE-2023-50564 - Pluck CMS v4.7.18 任意文件上传漏洞  
**类型:** 任意文件上传  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-05-24  
**POC仓库:** [CVE-2023-50564](https://github.com/Mrterrestrial/CVE-2023-50564)  

---

### [CVE-2023-50564](CVE-2023-50564-xpltive_CVE-2023-50564.md) 🔴 ✅

**名称:** CVE-2023-50564-PluckCMS-任意文件上传  
**类型:** 任意文件上传  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-05-24  
**POC仓库:** [CVE-2023-50564](https://github.com/xpltive/CVE-2023-50564)  

---

### [CVE-2023-50564](CVE-2023-50564-0xDTC_Pluck-CMS-v4.7.18-Remote-Code-Execution-CVE-2023-50564.md) 🔴 ✅

**名称:** CVE-2023-50564 Pluck-CMS v4.7.18 任意文件上传导致RCE  
**类型:** 任意文件上传  
**风险:** 高危，允许未经授权的攻击者执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-05-24  
**POC仓库:** [Pluck-CMS-v4.7.18-Remote-Code-Execution-CVE-2023-50564](https://github.com/0xDTC/Pluck-CMS-v4.7.18-Remote-Code-Execution-CVE-2023-50564)  

---

### [CVE-2023-50564](CVE-2023-50564-glynzr_CVE-2023-50564.md) 🔴 ✅

**名称:** CVE-2023-50564-Pluck-CMS-任意文件上传  
**类型:** 任意文件上传  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-05-24  
**POC仓库:** [CVE-2023-50564](https://github.com/glynzr/CVE-2023-50564)  

---

### [CVE-2025-25014](CVE-2025-25014-davidxbors_CVE-2025-25014.md) 🔴 ✅

**名称:** CVE-2025-25014-Kibana-Prototype Pollution  
**类型:** Prototype Pollution  
**风险:** 高危，可导致任意代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-05-24  
**POC仓库:** [CVE-2025-25014](https://github.com/davidxbors/CVE-2025-25014)  

---

### [CVE-2016-5180](CVE-2016-5180-pouriam23_final-CVE-2016-5180.md) 🔴 ✅

**名称:** CVE-2016-5180-c-ares 堆缓冲区溢出  
**类型:** 堆缓冲区溢出  
**风险:** 高危，可能导致拒绝服务或远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-05-24  
**POC仓库:** [final-CVE-2016-5180](https://github.com/pouriam23/final-CVE-2016-5180)  

---

### [CVE-2025-2294](CVE-2025-2294-0xWhoami35_CVE-2025-2294.md) 🔴 ✅

**名称:** CVE-2025-2294-Kubio AI Page Builder-LFI  
**类型:** 本地文件包含(LFI)  
**风险:** 高危，可能导致敏感信息泄露和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-05-24  
**POC仓库:** [CVE-2025-2294](https://github.com/0xWhoami35/CVE-2025-2294)  

---

### [CVE-2019-13288](CVE-2019-13288-gleaming0_CVE-2019-13288.md) 🔴 ✅

**名称:** CVE-2019-13288-Xpdf-无限递归DoS  
**类型:** 拒绝服务 (DoS)  
**风险:** 高危，导致应用程序崩溃或无响应  
**投毒风险:** 5%  
**发现时间:** 2025-05-24  
**POC仓库:** [CVE-2019-13288](https://github.com/gleaming0/CVE-2019-13288)  

---

### [CVE-2019-13288](CVE-2019-13288-Fineas_CVE-2019-13288-POC.md) 🔴 ✅

**名称:** CVE-2019-13288 - Xpdf Parser::getObj() 无限递归 DoS  
**类型:** 拒绝服务 (DoS)  
**风险:** 高危，可能导致服务不可用  
**投毒风险:** 10%  
**发现时间:** 2025-05-24  
**POC仓库:** [CVE-2019-13288-POC](https://github.com/Fineas/CVE-2019-13288-POC)  

---

### [CVE-2019-13288](CVE-2019-13288-WildWestCyberSecurity_CVE-2019-13288.md) 🟡 ✅

**名称:** CVE-2019-13288 - Xpdf Parser::getObj() 无限递归DoS  
**类型:** 拒绝服务 (DoS)  
**风险:** 中危，导致服务不可用  
**投毒风险:** 5%  
**发现时间:** 2025-05-24  
**POC仓库:** [CVE-2019-13288](https://github.com/WildWestCyberSecurity/CVE-2019-13288)  

---

### [CVE-2022-24112](CVE-2022-24112-kavishkagihan_CVE-2022-24112-POC.md) 🔴 ✅

**名称:** CVE-2022-24112-Apache APISIX-RCE  
**类型:** 远程代码执行  
**风险:** 高危，可导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-05-23  
**POC仓库:** [CVE-2022-24112-POC](https://github.com/kavishkagihan/CVE-2022-24112-POC)  

---

### [CVE-2022-24112](CVE-2022-24112-Mr-xn_CVE-2022-24112.md) 🔴 ✅

**名称:** CVE-2022-24112-Apache APISIX-RCE  
**类型:** 远程代码执行  
**风险:** 高危，可导致服务器完全控制  
**投毒风险:** 1%  
**发现时间:** 2025-05-23  
**POC仓库:** [CVE-2022-24112](https://github.com/Mr-xn/CVE-2022-24112)  

---

### [CVE-2022-24112](CVE-2022-24112-CrackerCat_CVE-2022-24112.md) 🔴 ✅

**名称:** CVE-2022-24112 - Apache APISIX Batch Requests RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 5%  
**发现时间:** 2025-05-23  
**POC仓库:** [CVE-2022-24112](https://github.com/CrackerCat/CVE-2022-24112)  

---

### [CVE-2022-24112](CVE-2022-24112-SecNN_CVE-2022-24112.md) 🔴 ✅

**名称:** CVE-2022-24112 Apache APISIX RCE  
**类型:** 远程代码执行  
**风险:** 高危，可完全控制服务器  
**投毒风险:** 10%  
**发现时间:** 2025-05-23  
**POC仓库:** [CVE-2022-24112](https://github.com/SecNN/CVE-2022-24112)  

---

### [CVE-2022-24112](CVE-2022-24112-Mah1ndra_CVE-2022-24112.md) 🔴 ✅

**名称:** CVE-2022-24112: Apache APISIX 远程代码执行漏洞  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可导致服务器完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-05-23  
**POC仓库:** [CVE-2022-24112](https://github.com/Mah1ndra/CVE-2022-24112)  

---

### [CVE-2022-24112](CVE-2022-24112-M4xSec_Apache-APISIX-CVE-2022-24112.md) 🔴 ✅

**名称:** CVE-2022-24112-Apache APISIX-RCE  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-05-23  
**POC仓库:** [Apache-APISIX-CVE-2022-24112](https://github.com/M4xSec/Apache-APISIX-CVE-2022-24112)  

---

### [CVE-2022-24112](CVE-2022-24112-twseptian_cve-2022-24112.md) 🔴 ✅

**名称:** CVE-2022-24112-Apache APISIX-RCE  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-05-23  
**POC仓库:** [cve-2022-24112](https://github.com/twseptian/cve-2022-24112)  

---

### [CVE-2022-24112](CVE-2022-24112-Acczdy_CVE-2022-24112_POC.md) 🔴 ✅

**名称:** CVE-2022-24112 - Apache APISIX 远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可导致服务器完全控制  
**投毒风险:** 5%  
**发现时间:** 2025-05-23  
**POC仓库:** [CVE-2022-24112_POC](https://github.com/Acczdy/CVE-2022-24112_POC)  

---

### [CVE-2022-24112](CVE-2022-24112-btar1gan_exploit_CVE-2022-24112.md) 🔴 ✅

**名称:** CVE-2022-24112-Apache APISIX-RCE  
**类型:** 远程代码执行  
**风险:** 高危，可导致服务器完全被控制  
**投毒风险:** 0%  
**发现时间:** 2025-05-23  
**POC仓库:** [exploit_CVE-2022-24112](https://github.com/btar1gan/exploit_CVE-2022-24112)  

---

### [CVE-2022-24112](CVE-2022-24112-fatkz_CVE-2022-24112.md) 🔴 ✅

**名称:** CVE-2022-24112-Apache APISIX-RCE  
**类型:** 远程代码执行  
**风险:** 高危，可导致服务器完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-05-23  
**POC仓库:** [CVE-2022-24112](https://github.com/fatkz/CVE-2022-24112)  

---

### [CVE-2025-31161](CVE-2025-31161-0xgh057r3c0n_CVE-2025-31161.md) 🔴 ✅

**名称:** CVE-2025-31161 - CrushFTP Authentication Bypass and User Creation Exploit  
**类型:** Authentication Bypass  
**风险:** 高危，可导致完全服务器控制  
**投毒风险:** 10%  
**发现时间:** 2025-05-23  
**POC仓库:** [CVE-2025-31161](https://github.com/0xgh057r3c0n/CVE-2025-31161)  

---

### [CVE-2022-26134](CVE-2022-26134-f4yd4-s3c_cve-2022-26134.md) 🔴 ✅

**名称:** CVE-2022-26134-Atlassian Confluence-OGNL注入  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，未经身份验证的攻击者可以执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-05-23  
**POC仓库:** [cve-2022-26134](https://github.com/f4yd4-s3c/cve-2022-26134)  

---

### [CVE-2019-25137](CVE-2019-25137-Ickarah_CVE-2019-25137-Version-Research.md) 🔴 ✅

**名称:** CVE-2019-25137 - Umbraco CMS Remote Code Execution  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，允许经过身份验证的管理员执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-05-23  
**POC仓库:** [CVE-2019-25137-Version-Research](https://github.com/Ickarah/CVE-2019-25137-Version-Research)  

---

### [CVE-2019-25137](CVE-2019-25137-dact91_CVE-2019-25137-RCE.md) 🔴 ✅

**名称:** CVE-2019-25137 - Umbraco CMS RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-05-23  
**POC仓库:** [CVE-2019-25137-RCE](https://github.com/dact91/CVE-2019-25137-RCE)  

---

### [CVE-2025-47181](CVE-2025-47181-encrypter15_CVE-2025-47181.md) 🔴 

**名称:** CVE-2025-47181: Microsoft Edge (Chromium-based) Update Elevation of Privilege Vulnerability  
**类型:** 权限提升  
**风险:** 高危，可能导致本地权限提升  
**投毒风险:** 10%  
**发现时间:** 2025-05-23  
**POC仓库:** [CVE-2025-47181](https://github.com/encrypter15/CVE-2025-47181)  

---

### [CVE-2021-3156](CVE-2021-3156-Shuhaib88_Baron-Samedit-Heap-Buffer-Overflow-CVE-2021-3156.md) 🔴 ✅

**名称:** CVE-2021-3156 (Baron Samedit)  
**类型:** 堆缓冲区溢出  
**风险:** 高危，允许本地用户提升权限至root  
**投毒风险:** 5%  
**发现时间:** 2025-05-23  
**POC仓库:** [Baron-Samedit-Heap-Buffer-Overflow-CVE-2021-3156](https://github.com/Shuhaib88/Baron-Samedit-Heap-Buffer-Overflow-CVE-2021-3156)  

---

### [CVE-2025-30400](CVE-2025-30400-encrypter15_CVE-2025-30400.md) 🔴 

**名称:** CVE-2025-30400 - Microsoft DWM Core Library Use-After-Free 提权漏洞  
**类型:** Use-After-Free 提权漏洞  
**风险:** 高危，本地提权至SYSTEM  
**投毒风险:** 10%  
**发现时间:** 2025-05-23  
**POC仓库:** [CVE-2025-30400](https://github.com/encrypter15/CVE-2025-30400)  

---

### [CVE-2024-12583](CVE-2024-12583-pouriam23_CVE-2024-12583.md)  

**名称:** CVE-2024-12583-Dynamics 365 Integration-RCE/Arbitrary File Read  
**类型:** 远程代码执行/任意文件读取  
**风险:** 严重，可能导致服务器完全控制和敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-05-23  
**POC仓库:** [CVE-2024-12583](https://github.com/pouriam23/CVE-2024-12583)  

---

### [CVE-2025-4123](CVE-2025-4123-kk12-30_CVE-2025-4123.md) 🔴 

**名称:** CVE-2025-4123-Grafana-XSS/SSRF  
**类型:** 跨站脚本 (XSS)/服务器端请求伪造 (SSRF)  
**风险:** 高危，可能导致任意JavaScript执行、SSRF、敏感信息泄露、账户接管  
**投毒风险:** 10%  
**发现时间:** 2025-05-23  
**POC仓库:** [CVE-2025-4123](https://github.com/kk12-30/CVE-2025-4123)  

---

### [CVE-2025-0133](CVE-2025-0133-dodiorne_cve-2025-0133.md) 🟡 ✅

**名称:** CVE-2025-0133-PAN-OS-Reflected XSS  
**类型:** Reflected XSS  
**风险:** 中危，可能导致凭据盗窃，特别是启用了 Clientless VPN 时  
**投毒风险:** 0%  
**发现时间:** 2025-05-23  
**POC仓库:** [cve-2025-0133](https://github.com/dodiorne/cve-2025-0133)  

---

### [CVE-2025-46801](CVE-2025-46801-korden-c_CVE-2025-46801.md) 🔴 ✅

**名称:** CVE-2025-46801 - Pgpool-II 认证绕过  
**类型:** 认证绕过  
**风险:** 高危，可能导致数据泄露、数据篡改和拒绝服务  
**投毒风险:** 20%  
**发现时间:** 2025-05-23  
**POC仓库:** [CVE-2025-46801](https://github.com/korden-c/CVE-2025-46801)  

---

### [CVE-2025-4918](CVE-2025-4918-korden-c_CVE-2025-4918.md) 🔴 ✅

**名称:** CVE-2025-4918 - Mozilla Firefox JavaScript Promise 对象越界访问  
**类型:** 内存破坏（越界读写）  
**风险:** 高危，可能导致远程代码执行或应用程序崩溃  
**投毒风险:** 60%  
**发现时间:** 2025-05-23  
**POC仓库:** [CVE-2025-4918](https://github.com/korden-c/CVE-2025-4918)  

---

### [CVE-2016-5180](CVE-2016-5180-pouriam23_CVE-2016-5180-docker-.md) 🔴 ✅

**名称:** CVE-2016-5180-c-ares 堆缓冲区溢出  
**类型:** 堆缓冲区溢出  
**风险:** 高危，可能导致拒绝服务或远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-05-23  
**POC仓库:** [CVE-2016-5180-docker-](https://github.com/pouriam23/CVE-2016-5180-docker-)  

---

### [CVE-2016-5180](CVE-2016-5180-pouriam23_CVE-2016-5180.md) 🔴 ✅

**名称:** CVE-2016-5180-c-ares 堆缓冲区溢出  
**类型:** 堆缓冲区溢出  
**风险:** 高危，可能导致拒绝服务或远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-05-23  
**POC仓库:** [CVE-2016-5180](https://github.com/pouriam23/CVE-2016-5180)  

---

### [CVE-2025-29927](CVE-2025-29927-enochgitgamefied_NextJS-CVE-2025-29927-Docker-Lab.md) 🔴 ✅

**名称:** CVE-2025-29927-Next.js中间件授权绕过  
**类型:** 授权绕过  
**风险:** 高危，可能导致未授权访问敏感数据和功能  
**投毒风险:** 10%  
**发现时间:** 2025-05-23  
**POC仓库:** [NextJS-CVE-2025-29927-Docker-Lab](https://github.com/enochgitgamefied/NextJS-CVE-2025-29927-Docker-Lab)  

---

### [CVE-2025-46822](CVE-2025-46822-d3sca_CVE-2025-46822.md) 🔴 ✅

**名称:** CVE-2025-46822-Java-springboot-codebase-绝对路径遍历导致任意文件读取  
**类型:** 绝对路径遍历/任意文件读取  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-05-23  
**POC仓库:** [CVE-2025-46822](https://github.com/d3sca/CVE-2025-46822)  

---

### [CVE-2025-4611](CVE-2025-4611-x6vrn_CVE-2025-4611-PoC.md) 🟡 ✅

**名称:** CVE-2025-4611-Slim SEO-存储型XSS  
**类型:** 存储型XSS  
**风险:** 中危，可能导致用户会话劫持、恶意脚本执行  
**投毒风险:** 0%  
**发现时间:** 2025-05-23  
**POC仓库:** [CVE-2025-4611-PoC](https://github.com/x6vrn/CVE-2025-4611-PoC)  

---

### [CVE-2023-48795](CVE-2023-48795-Eros-Adrian-Figueroa-Cortes_CVE-2023-48795.md) 🟡 ✅

**名称:** CVE-2023-48795-Terrapin Attack  
**类型:** SSH中间人攻击，降级加密  
**风险:** 中危，允许中间人攻击者通过截断 SSH 握手过程中的数据包，从而降级连接的安全性。  
**投毒风险:** 1%  
**发现时间:** 2025-05-23  
**POC仓库:** [CVE-2023-48795](https://github.com/Eros-Adrian-Figueroa-Cortes/CVE-2023-48795)  

---

### [CVE-2024-3661](CVE-2024-3661-Roundthe-clock_CVE-2024-3661VPN.md) 🔴 ✅

**名称:** CVE-2024-3661 TunnelVision VPN绕过  
**类型:** VPN绕过  
**风险:** 高危，可能导致VPN保护失效，流量泄露，数据被窃取或篡改  
**投毒风险:** 10%  
**发现时间:** 2025-05-23  
**POC仓库:** [CVE-2024-3661VPN](https://github.com/Roundthe-clock/CVE-2024-3661VPN)  

---

### [CVE-2025-44998](CVE-2025-44998-l8BL_CVE-2025-44998.md) 🟡 ✅

**名称:** CVE-2025-44998-TinyFileManager-存储型XSS  
**类型:** 存储型XSS  
**风险:** 中危，可能导致会话劫持，结合CVE-2022-40916可能导致任意用户登录  
**投毒风险:** 10%  
**发现时间:** 2025-05-23  
**POC仓库:** [CVE-2025-44998](https://github.com/l8BL/CVE-2025-44998)  

---

### [CVE-2023-48795](CVE-2023-48795-TrixSec_CVE-2023-48795.md) 🟡 ✅

**名称:** CVE-2023-48795 - SSH Terrapin攻击  
**类型:** 中间人攻击/协议降级  
**风险:** 中危，可能导致安全特性被降级或禁用，从而降低连接的安全性。  
**投毒风险:** 0%  
**发现时间:** 2025-05-23  
**POC仓库:** [CVE-2023-48795](https://github.com/TrixSec/CVE-2023-48795)  

---

### [CVE-2025-46801](CVE-2025-46801-xplitter_CVE-2025-46801.md) 🔴 ✅

**名称:** CVE-2025-46801 – Pgpool-II Authentication Bypass  
**类型:** 身份验证绕过  
**风险:** 高危，允许未经授权的数据库访问，可能导致数据泄露、篡改和拒绝服务。  
**投毒风险:** 80%  
**发现时间:** 2025-05-22  
**POC仓库:** [CVE-2025-46801](https://github.com/xplitter/CVE-2025-46801)  

---

### [CVE-2025-24799](CVE-2025-24799-galletitaconpate_CVE-2025-24799.md) 🔴 ✅

**名称:** CVE-2025-24799-GLPI-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露  
**投毒风险:** 10%  
**发现时间:** 2025-05-22  
**POC仓库:** [CVE-2025-24799](https://github.com/galletitaconpate/CVE-2025-24799)  

---

### [CVE-2024-9463](CVE-2024-9463-momo1239_CVE-2024-9463-Proof-of-Concept.md) 🔴 ✅

**名称:** CVE-2024-9463-Palo Alto Networks Expedition-OS 命令注入  
**类型:** OS 命令注入  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 5%  
**发现时间:** 2025-05-22  
**POC仓库:** [CVE-2024-9463-Proof-of-Concept](https://github.com/momo1239/CVE-2024-9463-Proof-of-Concept)  

---

### [CVE-2024-21762](CVE-2024-21762-rdoix_cve-2024-21762-checker.md) 🔴 ✅

**名称:** CVE-2024-21762 - Fortinet FortiOS/FortiProxy 越界写入  
**类型:** 越界写入  
**风险:** 高危，远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-05-22  
**POC仓库:** [cve-2024-21762-checker](https://github.com/rdoix/cve-2024-21762-checker)  

---

### [CVE-2024-21762](CVE-2024-21762-abrewer251_CVE-2024-21762_FortiNet_PoC.md) 🔴 ✅

**名称:** CVE-2024-21762 FortiOS SSL VPN 远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，远程未授权攻击者可以执行任意代码或命令  
**投毒风险:** 10%  
**发现时间:** 2025-05-22  
**POC仓库:** [CVE-2024-21762_FortiNet_PoC](https://github.com/abrewer251/CVE-2024-21762_FortiNet_PoC)  

---

### [CVE-2024-21762](CVE-2024-21762-h4x0r-dz_CVE-2024-21762.md) 🔴 ✅

**名称:** CVE-2024-21762 FortiOS/FortiProxy 远程代码执行  
**类型:** 越界写入 (Out-of-Bounds Write)  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-05-22  
**POC仓库:** [CVE-2024-21762](https://github.com/h4x0r-dz/CVE-2024-21762)  

---

### [CVE-2024-21762](CVE-2024-21762-d0rb_CVE-2024-21762.md) 🔴 ✅

**名称:** CVE-2024-21762-FortiOS/FortiProxy-Out-of-Bounds Write  
**类型:** Out-of-Bounds Write  
**风险:** 高危，远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-05-22  
**POC仓库:** [CVE-2024-21762](https://github.com/d0rb/CVE-2024-21762)  

---

### [CVE-2024-21762](CVE-2024-21762-r4p3c4_CVE-2024-21762-Exploit-PoC-Fortinet-SSL-VPN-Check.md) 🔴 ✅

**名称:** CVE-2024-21762-Fortinet FortiOS/FortiProxy 越界写  
**类型:** 越界写  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-05-22  
**POC仓库:** [CVE-2024-21762-Exploit-PoC-Fortinet-SSL-VPN-Check](https://github.com/r4p3c4/CVE-2024-21762-Exploit-PoC-Fortinet-SSL-VPN-Check)  

---

### [CVE-2024-21762](CVE-2024-21762-cleverg0d_CVE-2024-21762-Checker.md) 🔴 ✅

**名称:** CVE-2024-21762 - Fortinet FortiOS/FortiProxy 越界写  
**类型:** 越界写  
**风险:** 高危，远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-05-22  
**POC仓库:** [CVE-2024-21762-Checker](https://github.com/cleverg0d/CVE-2024-21762-Checker)  

---

### [CVE-2024-21762](CVE-2024-21762-BishopFox_cve-2024-21762-check.md)  ✅

**名称:** CVE-2024-21762 - FortiOS/FortiProxy 越界写入漏洞  
**类型:** 越界写入 (Out-of-bounds Write)  
**风险:** 严重，远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-05-22  
**POC仓库:** [cve-2024-21762-check](https://github.com/BishopFox/cve-2024-21762-check)  

---

### [CVE-2024-21762](CVE-2024-21762-XiaomingX_cve-2024-21762-poc.md)  ✅

**名称:** CVE-2024-21762-Fortinet-RCE  
**类型:** 越界写  
**风险:** 严重，未经身份验证的远程攻击者可以执行任意代码或命令。  
**投毒风险:** 0%  
**发现时间:** 2025-05-22  
**POC仓库:** [cve-2024-21762-poc](https://github.com/XiaomingX/cve-2024-21762-poc)  

---

### [CVE-2025-4322](CVE-2025-4322-Yucaerin_CVE-2025-4322.md)  ✅

**名称:** CVE-2025-4322 – Motors <= 5.6.67 - Unauthenticated Privilege Escalation via Password Update/Account Takeover  
**类型:** 权限提升/账户接管  
**风险:** 严重，可能导致完全的网站控制，数据泄露，恶意软件部署。  
**投毒风险:** 1%  
**发现时间:** 2025-05-22  
**POC仓库:** [CVE-2025-4322](https://github.com/Yucaerin/CVE-2025-4322)  

---

### [CVE-2025-4123](CVE-2025-4123-NightBloodz_CVE-2025-4123.md) 🔴 ✅

**名称:** CVE-2025-4123-Grafana-XSS/SSRF  
**类型:** XSS/SSRF  
**风险:** 高危，可能导致账号劫持，SSRF，以及任意JavaScript执行  
**投毒风险:** 10%  
**发现时间:** 2025-05-22  
**POC仓库:** [CVE-2025-4123](https://github.com/NightBloodz/CVE-2025-4123)  

---

### [CVE-2025-37899](CVE-2025-37899-SeanHeelan_o3_finds_cve-2025-37899.md) 🔴 ✅

**名称:** CVE-2025-37899 - Linux Kernel ksmbd use-after-free  
**类型:** Use-After-Free  
**风险:** 高危，可能导致拒绝服务或代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-05-22  
**POC仓库:** [o3_finds_cve-2025-37899](https://github.com/SeanHeelan/o3_finds_cve-2025-37899)  

---

### [CVE-2025-44108](CVE-2025-44108-harish0x_CVE-2025-44108-SXSS.md) 🟡 ✅

**名称:** CVE-2025-44108-Flatpress CMS-Stored XSS  
**类型:** Stored XSS  
**风险:** 中危，可能导致管理员会话劫持和恶意代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-05-22  
**POC仓库:** [CVE-2025-44108-SXSS](https://github.com/harish0x/CVE-2025-44108-SXSS)  

---

### [CVE-2021-34527](CVE-2021-34527-dywhoami_CVE-2021-34527-Scanner-Based-On-cube0x0-POC.md) 🔴 ✅

**名称:** CVE-2021-34527 PrintNightmare  
**类型:** 远程代码执行  
**风险:** 高危，允许攻击者以SYSTEM权限执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-05-22  
**POC仓库:** [CVE-2021-34527-Scanner-Based-On-cube0x0-POC](https://github.com/dywhoami/CVE-2021-34527-Scanner-Based-On-cube0x0-POC)  

---

### [CVE-2025-24085](CVE-2025-24085-apt-007_12345.md) 🔴 ✅

**名称:** CVE-2025-24085-Apple-Use-After-Free-Privilege-Escalation  
**类型:** Use-After-Free权限提升  
**风险:** 高危，允许恶意应用程序提升权限  
**投毒风险:** 10%  
**发现时间:** 2025-05-21  
**POC仓库:** [12345](https://github.com/apt-007/12345)  

---

### [CVE-2025-4322](CVE-2025-4322-maximo896_CVE-2025-4322.md)  ✅

**名称:** CVE-2025-4322-Motors主题-权限提升/账户接管  
**类型:** 权限提升/账户接管  
**风险:** 严重，允许未经身份验证的攻击者更改任意用户密码，包括管理员密码，并利用该密码访问其帐户。  
**投毒风险:** 95%  
**发现时间:** 2025-05-21  
**POC仓库:** [CVE-2025-4322](https://github.com/maximo896/CVE-2025-4322)  

---

### [CVE-2021-34527](CVE-2021-34527-geekbrett_CVE-2021-34527-PrintNightmare-Workaround.md) 🔴 ✅

**名称:** CVE-2021-34527 PrintNightmare Windows Print Spooler RCE  
**类型:** 远程代码执行  
**风险:** 高危，允许攻击者以SYSTEM权限执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-05-21  
**POC仓库:** [CVE-2021-34527-PrintNightmare-Workaround](https://github.com/geekbrett/CVE-2021-34527-PrintNightmare-Workaround)  

---

### [CVE-2021-34527](CVE-2021-34527-glorisonlai_printnightmare.md) 🔴 ✅

**名称:** CVE-2021-34527 PrintNightmare  
**类型:** 远程代码执行  
**风险:** 高危，可导致SYSTEM权限的远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-05-21  
**POC仓库:** [printnightmare](https://github.com/glorisonlai/printnightmare)  

---

### [CVE-2021-34527](CVE-2021-34527-rdboboia_disable-RegisterSpoolerRemoteRpcEndPoint.md) 🔴 ✅

**名称:** CVE-2021-34527 PrintNightmare  
**类型:** 远程代码执行  
**风险:** 高危，允许未经授权的用户通过Print Spooler服务远程执行代码，可能导致完全系统控制  
**投毒风险:** 10%  
**发现时间:** 2025-05-21  
**POC仓库:** [disable-RegisterSpoolerRemoteRpcEndPoint](https://github.com/rdboboia/disable-RegisterSpoolerRemoteRpcEndPoint)  

---

### [CVE-2021-34527](CVE-2021-34527-WidespreadPandemic_CVE-2021-34527_ACL_mitigation.md) 🔴 ✅

**名称:** CVE-2021-34527 PrintNightmare  
**类型:** 远程代码执行  
**风险:** 高危，允许攻击者以SYSTEM权限执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-05-21  
**POC仓库:** [CVE-2021-34527_ACL_mitigation](https://github.com/WidespreadPandemic/CVE-2021-34527_ACL_mitigation)  

---

### [CVE-2021-34527](CVE-2021-34527-Eutectico_Printnightmare.md) 🔴 ✅

**名称:** CVE-2021-34527 PrintNightmare  
**类型:** 远程代码执行  
**风险:** 高危，允许攻击者以SYSTEM权限执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-05-21  
**POC仓库:** [Printnightmare](https://github.com/Eutectico/Printnightmare)  

---

### [CVE-2021-34527](CVE-2021-34527-syntaxbearror_PowerShell-PrintNightmare.md) 🔴 

**名称:** CVE-2021-34527 PrintNightmare Windows Print Spooler Remote Code Execution  
**类型:** 远程代码执行  
**风险:** 高危，允许攻击者以SYSTEM权限执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-05-21  
**POC仓库:** [PowerShell-PrintNightmare](https://github.com/syntaxbearror/PowerShell-PrintNightmare)  

---

### [CVE-2021-34527](CVE-2021-34527-thomas-lauer_PrintNightmare.md) 🔴 ✅

**名称:** CVE-2021-34527 PrintNightmare  
**类型:** 远程代码执行  
**风险:** 高危，允许攻击者以SYSTEM权限执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-05-21  
**POC仓库:** [PrintNightmare](https://github.com/thomas-lauer/PrintNightmare)  

---

### [CVE-2021-34527](CVE-2021-34527-0xirison_PrintNightmare-Patcher.md) 🔴 ✅

**名称:** CVE-2021-34527 PrintNightmare  
**类型:** 远程代码执行  
**风险:** 高危，允许未经授权的用户以SYSTEM权限执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-05-21  
**POC仓库:** [PrintNightmare-Patcher](https://github.com/0xirison/PrintNightmare-Patcher)  

---

### [CVE-2021-34527](CVE-2021-34527-Tomparte_PrintNightmare.md) 🔴 ✅

**名称:** CVE-2021-34527 PrintNightmare  
**类型:** 远程代码执行 (RCE) / 本地提权 (LPE)  
**风险:** 高危，可能导致远程代码执行和系统权限提升  
**投毒风险:** 10%  
**发现时间:** 2025-05-21  
**POC仓库:** [PrintNightmare](https://github.com/Tomparte/PrintNightmare)  

---

### [CVE-2021-34527](CVE-2021-34527-nemo-wq_PrintNightmare-CVE-2021-34527.md) 🔴 ✅

**名称:** CVE-2021-34527 - PrintNightmare  
**类型:** 远程代码执行  
**风险:** 高危，允许攻击者以 SYSTEM 权限执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-05-21  
**POC仓库:** [PrintNightmare-CVE-2021-34527](https://github.com/nemo-wq/PrintNightmare-CVE-2021-34527)  

---

### [CVE-2021-34527](CVE-2021-34527-Amaranese_CVE-2021-34527.md) 🔴 ✅

**名称:** CVE-2021-34527 - PrintNightmare  
**类型:** 远程代码执行  
**风险:** 高危，可导致SYSTEM权限的远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-05-21  
**POC仓库:** [CVE-2021-34527](https://github.com/Amaranese/CVE-2021-34527)  

---

### [CVE-2021-34527](CVE-2021-34527-cyb3rpeace_CVE-2021-34527.md) 🔴 ✅

**名称:** CVE-2021-34527 PrintNightmare  
**类型:** 远程代码执行  
**风险:** 高危，允许未经授权的用户以SYSTEM权限执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-05-21  
**POC仓库:** [CVE-2021-34527](https://github.com/cyb3rpeace/CVE-2021-34527)  

---

### [CVE-2021-34527](CVE-2021-34527-hackerhouse-opensource_cve-2021-34527.md) 🔴 ✅

**名称:** CVE-2021-34527 PrintNightmare Windows Print Spooler RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可导致系统权限提升和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-05-21  
**POC仓库:** [cve-2021-34527](https://github.com/hackerhouse-opensource/cve-2021-34527)  

---

### [CVE-2021-34527](CVE-2021-34527-m8sec_CVE-2021-34527.md) 🔴 ✅

**名称:** CVE-2021-34527 - PrintNightmare Windows Print Spooler RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，攻击者可以以 SYSTEM 权限执行任意代码。  
**投毒风险:** 10%  
**发现时间:** 2025-05-21  
**POC仓库:** [CVE-2021-34527](https://github.com/m8sec/CVE-2021-34527)  

---

### [CVE-2021-34527](CVE-2021-34527-d0rb_CVE-2021-34527.md) 🔴 ✅

**名称:** CVE-2021-34527 PrintNightmare  
**类型:** 远程代码执行  
**风险:** 高危，允许攻击者以SYSTEM权限执行任意代码  
**投毒风险:** 0%  
**发现时间:** 2025-05-21  
**POC仓库:** [CVE-2021-34527](https://github.com/d0rb/CVE-2021-34527)  

---

### [CVE-2021-34527](CVE-2021-34527-byt3bl33d3r_ItWasAllADream.md) 🔴 ✅

**名称:** CVE-2021-34527 PrintNightmare RCE  
**类型:** 远程代码执行  
**风险:** 高危，允许攻击者以SYSTEM权限执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-05-21  
**POC仓库:** [ItWasAllADream](https://github.com/byt3bl33d3r/ItWasAllADream)  

---

### [CVE-2021-34527](CVE-2021-34527-AUSK1LL9_CVE-2021-34527.md) 🔴 ✅

**名称:** CVE-2021-34527 PrintNightmare Windows Print Spooler Remote Code Execution Vulnerability  
**类型:** 远程代码执行 (RCE) / 本地权限提升 (LPE)  
**风险:** 高危，可能导致远程代码执行，系统完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-05-21  
**POC仓库:** [CVE-2021-34527](https://github.com/AUSK1LL9/CVE-2021-34527)  

---

### [CVE-2022-31813](CVE-2022-31813-dodiorne_cve-2022-31813.md) 🟡 ✅

**名称:** CVE-2022-31813-Apache HTTP Server-X-Forwarded-For绕过  
**类型:** HTTP Header Spoofing (X-Forwarded-For Bypass)  
**风险:** 中危，可能导致IP地址认证绕过  
**投毒风险:** 10%  
**发现时间:** 2025-05-21  
**POC仓库:** [cve-2022-31813](https://github.com/dodiorne/cve-2022-31813)  

---

### [CVE-2024-12583](CVE-2024-12583-pouriam23_CVE-2024-12583-.md) 🔴 

**名称:** CVE-2024-12583-Dynamics 365 Integration-RCE  
**类型:** 远程代码执行  
**风险:** 高危，可完全控制服务器  
**投毒风险:** 10%  
**发现时间:** 2025-05-21  
**POC仓库:** [CVE-2024-12583-](https://github.com/pouriam23/CVE-2024-12583-)  

---

### [CVE-2025-12654](CVE-2025-12654-Laertharaz_Anydesk-Exploit-CVE-2025-12654-RCE-Builder.md) 🔴 ✅

**名称:** CVE-2025-12654/CVE-2020-13160/CVE-2019-14743 AnyDesk 漏洞利用  
**类型:** RCE/DLL劫持/认证绕过/信息泄露  
**风险:** 高危，可能导致远程代码执行、敏感信息泄露和未授权访问  
**投毒风险:** 50%  
**发现时间:** 2025-05-21  
**POC仓库:** [Anydesk-Exploit-CVE-2025-12654-RCE-Builder](https://github.com/Laertharaz/Anydesk-Exploit-CVE-2025-12654-RCE-Builder)  

---

### [CVE-2025-4918](CVE-2025-4918-hendrewna_CVE-2025-4918.md) 🔴 ✅

**名称:** CVE-2025-4918-Firefox-OOB越界读写  
**类型:** 内存损坏（越界读写）  
**风险:** 高危，可能导致远程代码执行或应用崩溃  
**投毒风险:** 50%  
**发现时间:** 2025-05-21  
**POC仓库:** [CVE-2025-4918](https://github.com/hendrewna/CVE-2025-4918)  

---

### [CVE-2022-46169](CVE-2022-46169-a1665454764_CVE-2022-46169.md) 🔴 ✅

**名称:** CVE-2022-46169-Cacti-远程命令执行  
**类型:** 远程命令执行  
**风险:** 高危，允许未经身份验证的攻击者执行任意命令  
**投毒风险:** 1%  
**发现时间:** 2025-05-21  
**POC仓库:** [CVE-2022-46169](https://github.com/a1665454764/CVE-2022-46169)  

---

### [CVE-2022-46169](CVE-2022-46169-FredBrave_CVE-2022-46169-CACTI-1.2.22.md) 🔴 ✅

**名称:** CVE-2022-46169-Cacti-命令注入  
**类型:** 命令注入  
**风险:** 高危，允许未经身份验证的攻击者执行任意代码  
**投毒风险:** 5%  
**发现时间:** 2025-05-21  
**POC仓库:** [CVE-2022-46169-CACTI-1.2.22](https://github.com/FredBrave/CVE-2022-46169-CACTI-1.2.22)  

---

### [CVE-2025-46801](CVE-2025-46801-hendrewna_CVE-2025-46801.md) 🔴 ✅

**名称:** CVE-2025-46801 – Pgpool-II Authentication Bypass  
**类型:** Authentication Bypass  
**风险:** 高危，允许未授权访问数据库，篡改或读取数据，甚至可能导致服务中断。  
**投毒风险:** 20%  
**发现时间:** 2025-05-21  
**POC仓库:** [CVE-2025-46801](https://github.com/hendrewna/CVE-2025-46801)  

---

### [CVE-2022-46169](CVE-2022-46169-N1arut_CVE-2022-46169_POC.md) 🔴 ✅

**名称:** CVE-2022-46169-Cacti-命令注入  
**类型:** 命令注入  
**风险:** 高危，允许未经身份验证的远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-05-21  
**POC仓库:** [CVE-2022-46169_POC](https://github.com/N1arut/CVE-2022-46169_POC)  

---

### [CVE-2022-46169](CVE-2022-46169-Habib0x0_CVE-2022-46169.md) 🔴 ✅

**名称:** CVE-2022-46169 - Cacti 未授权命令注入  
**类型:** 命令注入  
**风险:** 高危，未经身份验证的远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-05-21  
**POC仓库:** [CVE-2022-46169](https://github.com/Habib0x0/CVE-2022-46169)  

---

### [CVE-2022-46169](CVE-2022-46169-miko550_CVE-2022-46169.md) 🔴 ✅

**名称:** CVE-2022-46169-Cacti-命令注入  
**类型:** 命令注入  
**风险:** 高危，允许未经身份验证的攻击者执行任意操作系统命令。  
**投毒风险:** 5%  
**发现时间:** 2025-05-21  
**POC仓库:** [CVE-2022-46169](https://github.com/miko550/CVE-2022-46169)  

---

### [CVE-2022-46169](CVE-2022-46169-doosec101_CVE-2022-46169.md) 🔴 ✅

**名称:** CVE-2022-46169-Cacti-命令注入  
**类型:** 命令注入  
**风险:** 高危，允许未经身份验证的攻击者执行任意命令  
**投毒风险:** 0%  
**发现时间:** 2025-05-21  
**POC仓库:** [CVE-2022-46169](https://github.com/doosec101/CVE-2022-46169)  

---

### [CVE-2022-46169](CVE-2022-46169-m3ssap0_cacti-rce-cve-2022-46169-vulnerable-application.md) 🔴 ✅

**名称:** CVE-2022-46169 - Cacti 未授权命令注入  
**类型:** 命令注入  
**风险:** 高危，允许未授权用户执行任意代码  
**投毒风险:** 5%  
**发现时间:** 2025-05-21  
**POC仓库:** [cacti-rce-cve-2022-46169-vulnerable-application](https://github.com/m3ssap0/cacti-rce-cve-2022-46169-vulnerable-application)  

---

### [CVE-2022-46169](CVE-2022-46169-JacobEbben_CVE-2022-46169_unauth_remote_code_execution.md) 🔴 ✅

**名称:** CVE-2022-46169 - Cacti Unauthenticated Remote Code Execution  
**类型:** 命令注入  
**风险:** 高危，允许未经身份验证的攻击者执行任意命令  
**投毒风险:** 1%  
**发现时间:** 2025-05-21  
**POC仓库:** [CVE-2022-46169_unauth_remote_code_execution](https://github.com/JacobEbben/CVE-2022-46169_unauth_remote_code_execution)  

---

### [CVE-2022-46169](CVE-2022-46169-icebreack_CVE-2022-46169.md) 🔴 ✅

**名称:** CVE-2022-46169-Cacti-远程命令执行  
**类型:** 远程命令执行 (RCE)  
**风险:** 高危，允许未经身份验证的攻击者执行任意命令  
**投毒风险:** 0%  
**发现时间:** 2025-05-21  
**POC仓库:** [CVE-2022-46169](https://github.com/icebreack/CVE-2022-46169)  

---

### [CVE-2022-46169](CVE-2022-46169-devAL3X_CVE-2022-46169_poc.md) 🔴 ✅

**名称:** CVE-2022-46169-Cacti-命令注入  
**类型:** 命令注入  
**风险:** 高危，允许未经身份验证的攻击者执行任意命令  
**投毒风险:** 0%  
**发现时间:** 2025-05-21  
**POC仓库:** [CVE-2022-46169_poc](https://github.com/devAL3X/CVE-2022-46169_poc)  

---

### [CVE-2022-46169](CVE-2022-46169-devilgothies_CVE-2022-46169.md) 🔴 ✅

**名称:** CVE-2022-46169-Cacti-命令注入  
**类型:** 命令注入  
**风险:** 高危，允许未经身份验证的远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-05-21  
**POC仓库:** [CVE-2022-46169](https://github.com/devilgothies/CVE-2022-46169)  

---

### [CVE-2022-46169](CVE-2022-46169-yassinebk_CVE-2022-46169.md) 🔴 ✅

**名称:** CVE-2022-46169-Cacti-命令注入  
**类型:** 命令注入  
**风险:** 高危，允许未授权的远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-05-21  
**POC仓库:** [CVE-2022-46169](https://github.com/yassinebk/CVE-2022-46169)  

---

### [CVE-2022-46169](CVE-2022-46169-r1nzleer_RCE-Cacti-1.2.22.md) 🔴 ✅

**名称:** CVE-2022-46169-Cacti-命令注入  
**类型:** 命令注入  
**风险:** 高危，允许未经身份验证的用户执行任意命令  
**投毒风险:** 5%  
**发现时间:** 2025-05-21  
**POC仓库:** [RCE-Cacti-1.2.22](https://github.com/r1nzleer/RCE-Cacti-1.2.22)  

---

### [CVE-2022-46169](CVE-2022-46169-Safarchand_CVE-2022-46169.md) 🔴 ✅

**名称:** CVE-2022-46169-Cacti-命令注入  
**类型:** 命令注入  
**风险:** 高危，允许未授权的远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-05-21  
**POC仓库:** [CVE-2022-46169](https://github.com/Safarchand/CVE-2022-46169)  

---

### [CVE-2022-46169](CVE-2022-46169-MarkStrendin_CVE-2022-46169.md) 🔴 ✅

**名称:** CVE-2022-46169-Cacti-命令注入  
**类型:** 命令注入  
**风险:** 高危，未经身份验证的远程命令执行  
**投毒风险:** 5%  
**发现时间:** 2025-05-21  
**POC仓库:** [CVE-2022-46169](https://github.com/MarkStrendin/CVE-2022-46169)  

---

### [CVE-2022-46169](CVE-2022-46169-BKreisel_CVE-2022-46169.md) 🔴 ✅

**名称:** CVE-2022-46169-Cacti-命令注入  
**类型:** 命令注入  
**风险:** 高危，未经身份验证的远程命令执行  
**投毒风险:** 5%  
**发现时间:** 2025-05-21  
**POC仓库:** [CVE-2022-46169](https://github.com/BKreisel/CVE-2022-46169)  

---

### [CVE-2022-46169](CVE-2022-46169-sAsPeCt488_CVE-2022-46169.md) 🔴 ✅

**名称:** CVE-2022-46169-Cacti-命令注入  
**类型:** 命令注入  
**风险:** 高危，允许未授权用户执行任意命令  
**投毒风险:** 0%  
**发现时间:** 2025-05-21  
**POC仓库:** [CVE-2022-46169](https://github.com/sAsPeCt488/CVE-2022-46169)  

---

### [CVE-2022-46169](CVE-2022-46169-Rickster5555_EH2-PoC.md) 🔴 ✅

**名称:** CVE-2022-46169-Cacti-命令注入  
**类型:** 命令注入  
**风险:** 高危，允许未授权用户执行任意命令  
**投毒风险:** 5%  
**发现时间:** 2025-05-21  
**POC仓库:** [EH2-PoC](https://github.com/Rickster5555/EH2-PoC)  

---

### [CVE-2022-46169](CVE-2022-46169-ariyaadinatha_cacti-cve-2022-46169-exploit.md) 🔴 ✅

**名称:** CVE-2022-46169-Cacti-命令注入  
**类型:** 命令注入  
**风险:** 高危，未经身份验证的远程命令执行  
**投毒风险:** 5%  
**发现时间:** 2025-05-21  
**POC仓库:** [cacti-cve-2022-46169-exploit](https://github.com/ariyaadinatha/cacti-cve-2022-46169-exploit)  

---

### [CVE-2022-46169](CVE-2022-46169-antisecc_CVE-2022-46169.md) 🔴 ✅

**名称:** CVE-2022-46169-Cacti-命令注入  
**类型:** 命令注入  
**风险:** 高危，允许未经身份验证的攻击者执行任意命令  
**投毒风险:** 5%  
**发现时间:** 2025-05-21  
**POC仓库:** [CVE-2022-46169](https://github.com/antisecc/CVE-2022-46169)  

---

### [CVE-2022-46169](CVE-2022-46169-dawnl3ss_CVE-2022-46169.md) 🔴 ✅

**名称:** CVE-2022-46169-Cacti-命令注入  
**类型:** 命令注入  
**风险:** 高危，未经身份验证的远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-05-21  
**POC仓库:** [CVE-2022-46169](https://github.com/dawnl3ss/CVE-2022-46169)  

---

### [CVE-2022-46169](CVE-2022-46169-0xZon_CVE-2022-46169-Exploit.md) 🔴 ✅

**名称:** CVE-2022-46169-Cacti-命令注入  
**类型:** 命令注入  
**风险:** 高危，允许未经身份验证的攻击者执行任意命令  
**投毒风险:** 0%  
**发现时间:** 2025-05-21  
**POC仓库:** [CVE-2022-46169-Exploit](https://github.com/0xZon/CVE-2022-46169-Exploit)  

---

### [CVE-2022-46169](CVE-2022-46169-copyleftdev_PricklyPwn.md) 🔴 ✅

**名称:** CVE-2022-46169-Cacti-命令注入  
**类型:** 命令注入  
**风险:** 高危，允许未授权的远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-05-21  
**POC仓库:** [PricklyPwn](https://github.com/copyleftdev/PricklyPwn)  

---

### [CVE-2022-46169](CVE-2022-46169-ruycr4ft_CVE-2022-46169.md) 🔴 ✅

**名称:** CVE-2022-46169-Cacti-命令注入  
**类型:** 命令注入  
**风险:** 高危，允许未经身份验证的远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-05-21  
**POC仓库:** [CVE-2022-46169](https://github.com/ruycr4ft/CVE-2022-46169)  

---

### [CVE-2022-46169](CVE-2022-46169-0xN7y_CVE-2022-46169.md) 🔴 ✅

**名称:** CVE-2022-46169-Cacti-命令注入  
**类型:** 命令注入  
**风险:** 高危，允许未授权用户执行任意命令  
**投毒风险:** 5%  
**发现时间:** 2025-05-21  
**POC仓库:** [CVE-2022-46169](https://github.com/0xN7y/CVE-2022-46169)  

---

### [CVE-2022-46169](CVE-2022-46169-mind2hex_CVE-2022-46169.md) 🔴 ✅

**名称:** CVE-2022-46169-Cacti-命令注入  
**类型:** 命令注入  
**风险:** 高危，允许未授权用户执行任意命令  
**投毒风险:** 0%  
**发现时间:** 2025-05-21  
**POC仓库:** [CVE-2022-46169](https://github.com/mind2hex/CVE-2022-46169)  

---

### [CVE-2022-46169](CVE-2022-46169-HPT-Intern-Task-Submission_CVE-2022-46169.md)  ✅

**名称:** CVE-2022-46169 - Cacti 未授权远程代码执行  
**类型:** 命令注入  
**风险:** 严重，未经身份验证的远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-05-21  
**POC仓库:** [CVE-2022-46169](https://github.com/HPT-Intern-Task-Submission/CVE-2022-46169)  

---

### [CVE-2022-46169](CVE-2022-46169-lof1sec_CVE-2022-46169.md) 🔴 ✅

**名称:** CVE-2022-46169-Cacti-命令注入  
**类型:** 命令注入  
**风险:** 高危，允许未经身份验证的远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-05-21  
**POC仓库:** [CVE-2022-46169](https://github.com/lof1sec/CVE-2022-46169)  

---

### [CVE-2022-46169](CVE-2022-46169-RdBBB3_SHELL-POC-CVE-2022-46169.md) 🔴 ✅

**名称:** CVE-2022-46169-Cacti-命令注入  
**类型:** 命令注入  
**风险:** 高危，允许未授权用户执行任意命令  
**投毒风险:** 5%  
**发现时间:** 2025-05-21  
**POC仓库:** [SHELL-POC-CVE-2022-46169](https://github.com/RdBBB3/SHELL-POC-CVE-2022-46169)  

---

### [CVE-2017-10003](CVE-2017-10003-homjxi0e_CVE-2017-1000367.md) 🔴 ✅

**名称:** CVE-2017-1000367 - Sudo权限提升漏洞  
**类型:** 权限提升  
**风险:** 高危，可能导致本地用户获取root权限  
**投毒风险:** 10%  
**发现时间:** 2025-05-21  
**POC仓库:** [CVE-2017-1000367](https://github.com/homjxi0e/CVE-2017-1000367)  

---

### [CVE-2017-10003](CVE-2017-10003-c0d3z3r0_sudo-CVE-2017-1000367.md) 🟡 ✅

**名称:** CVE-2017-10003  
**类型:** Solaris权限提升/数据篡改/DoS  
**风险:** 中危，可能导致未授权数据修改、读取和部分拒绝服务  
**投毒风险:** 10%  
**发现时间:** 2025-05-21  
**POC仓库:** [sudo-CVE-2017-1000367](https://github.com/c0d3z3r0/sudo-CVE-2017-1000367)  

---

### [CVE-2017-10003](CVE-2017-10003-r00t4dm_Jenkins-CVE-2017-1000353.md) 🟡 ✅

**名称:** CVE-2017-10003  
**类型:** 权限提升/信息泄露/DoS  
**风险:** 中危，可能导致未授权数据访问、修改或拒绝服务  
**投毒风险:** 0%  
**发现时间:** 2025-05-21  
**POC仓库:** [Jenkins-CVE-2017-1000353](https://github.com/r00t4dm/Jenkins-CVE-2017-1000353)  

---

### [CVE-2017-10003](CVE-2017-10003-Trinadh465_linux-4.1.15_CVE-2017-1000371.md) 🟡 

**名称:** CVE-2017-10003-Oracle Solaris Network Services Library权限提升/信息泄露/DoS  
**类型:** 权限提升/信息泄露/DoS  
**风险:** 中危，可能导致敏感数据泄露、部分数据篡改和部分服务拒绝  
**投毒风险:** 99%  
**发现时间:** 2025-05-21  
**POC仓库:** [linux-4.1.15_CVE-2017-1000371](https://github.com/Trinadh465/linux-4.1.15_CVE-2017-1000371)  

---

### [CVE-2017-10003](CVE-2017-10003-vulhub_CVE-2017-1000353.md) 🟡 

**名称:** CVE-2017-10003  
**类型:** Solaris Network Services Library 权限提升/DoS  
**风险:** 中危，可能导致数据修改、信息泄露和部分拒绝服务  
**投毒风险:** 0%  
**发现时间:** 2025-05-21  
**POC仓库:** [CVE-2017-1000353](https://github.com/vulhub/CVE-2017-1000353)  

---

### [CVE-2022-21449](CVE-2022-21449-jmiettinen_CVE-2022-21449-vuln-test.md) 🔴 ✅

**名称:** CVE-2022-21449 - Java ECDSA 签名绕过 (Psychic Signatures)  
**类型:** 身份验证绕过  
**风险:** 高危，可能导致未经授权的访问和数据篡改  
**投毒风险:** 0%  
**发现时间:** 2025-05-21  
**POC仓库:** [CVE-2022-21449-vuln-test](https://github.com/jmiettinen/CVE-2022-21449-vuln-test)  

---

### [CVE-2022-21449](CVE-2022-21449-notkmhn_CVE-2022-21449-TLS-PoC.md) 🔴 ✅

**名称:** CVE-2022-21449 Psychic Signatures  
**类型:** ECDSA签名绕过  
**风险:** 高危，允许未经验证的攻击者修改数据  
**投毒风险:** 10%  
**发现时间:** 2025-05-21  
**POC仓库:** [CVE-2022-21449-TLS-PoC](https://github.com/notkmhn/CVE-2022-21449-TLS-PoC)  

---

### [CVE-2022-21449](CVE-2022-21449-marschall_psychic-signatures.md) 🔴 ✅

**名称:** CVE-2022-21449 - Psychic Signatures  
**类型:** ECDSA 签名绕过  
**风险:** 高危，未经授权的数据创建、删除或修改  
**投毒风险:** 10%  
**发现时间:** 2025-05-21  
**POC仓库:** [psychic-signatures](https://github.com/marschall/psychic-signatures)  

---

### [CVE-2022-21449](CVE-2022-21449-jfrog_jfrog-CVE-2022-21449.md) 🔴 ✅

**名称:** CVE-2022-21449 - Java ECDSA Psychic Signatures  
**类型:** 身份验证绕过  
**风险:** 高危，允许未授权的攻击者执行操作，修改数据  
**投毒风险:** 5%  
**发现时间:** 2025-05-21  
**POC仓库:** [jfrog-CVE-2022-21449](https://github.com/jfrog/jfrog-CVE-2022-21449)  

---

### [CVE-2022-21449](CVE-2022-21449-Damok82_SignChecker.md) 🔴 ✅

**名称:** CVE-2022-21449-Java ECDSA 签名绕过  
**类型:** 签名绕过  
**风险:** 高危，允许未授权的创建、删除或修改关键数据或所有可访问的数据。  
**投毒风险:** 0%  
**发现时间:** 2025-05-21  
**POC仓库:** [SignChecker](https://github.com/Damok82/SignChecker)  

---

### [CVE-2022-21449](CVE-2022-21449-thack1_CVE-2022-21449.md) 🔴 ✅

**名称:** CVE-2022-21449 Psychic Signatures  
**类型:** ECDSA 签名绕过  
**风险:** 高危，可能导致身份验证绕过和未授权访问  
**投毒风险:** 0%  
**发现时间:** 2025-05-21  
**POC仓库:** [CVE-2022-21449](https://github.com/thack1/CVE-2022-21449)  

---

### [CVE-2022-21449](CVE-2022-21449-Skipper7718_CVE-2022-21449-showcase.md) 🔴 ✅

**名称:** CVE-2022-21449 Psychic Signatures Java Vulnerability  
**类型:** ECDSA签名绕过  
**风险:** 高危，允许未授权的创建、删除或修改关键数据  
**投毒风险:** 10%  
**发现时间:** 2025-05-21  
**POC仓库:** [CVE-2022-21449-showcase](https://github.com/Skipper7718/CVE-2022-21449-showcase)  

---

### [CVE-2022-21449](CVE-2022-21449-davwwwx_CVE-2022-21449.md) 🔴 ✅

**名称:** CVE-2022-21449 - Java ECDSA Psychic Signatures  
**类型:** 身份验证绕过  
**风险:** 高危，可能导致未经授权的数据访问、修改或删除  
**投毒风险:** 10%  
**发现时间:** 2025-05-21  
**POC仓库:** [CVE-2022-21449](https://github.com/davwwwx/CVE-2022-21449)  

---

### [CVE-2022-21449](CVE-2022-21449-AlexanderZinoni_CVE-2022-21449.md) 🔴 ✅

**名称:** CVE-2022-21449 - Java ECDSA Psychic Signatures  
**类型:** ECDSA 签名绕过  
**风险:** 高危，允许未经身份验证的攻击者修改关键数据。  
**投毒风险:** 10%  
**发现时间:** 2025-05-21  
**POC仓库:** [CVE-2022-21449](https://github.com/AlexanderZinoni/CVE-2022-21449)  

---

### [CVE-2022-21449](CVE-2022-21449-HeyMrSalt_AIS3-2024-Project-D5Team.md) 🔴 ✅

**名称:** CVE-2022-21449-Java-Psychic Signatures  
**类型:** ECDSA签名绕过  
**风险:** 高危，可能导致未授权的数据创建、删除或修改  
**投毒风险:** 0%  
**发现时间:** 2025-05-21  
**POC仓库:** [AIS3-2024-Project-D5Team](https://github.com/HeyMrSalt/AIS3-2024-Project-D5Team)  

---

### [CVE-2022-21449](CVE-2022-21449-volodymyr-hladkyi-symphony_demo-cve-2022-21449.md) 🔴 ✅

**名称:** CVE-2022-21449 - Java ECDSA 签名绕过  
**类型:** 签名绕过  
**风险:** 高危，可能导致未授权访问和数据篡改  
**投毒风险:** 1%  
**发现时间:** 2025-05-21  
**POC仓库:** [demo-cve-2022-21449](https://github.com/volodymyr-hladkyi-symphony/demo-cve-2022-21449)  

---

### [CVE-2024-56429](CVE-2024-56429-lisa-2905_CVE-2024-56429.md) 🟡 ✅

**名称:** CVE-2024-56429-iLabClient-数据库密码泄露及数据操纵  
**类型:** 信息泄露/权限提升  
**风险:** 中危，可能导致敏感数据泄露和本地权限提升  
**投毒风险:** 0%  
**发现时间:** 2025-05-21  
**POC仓库:** [CVE-2024-56429](https://github.com/lisa-2905/CVE-2024-56429)  

---

### [CVE-2024-56428](CVE-2024-56428-lisa-2905_CVE-2024-56428.md) 🟡 ✅

**名称:** CVE-2024-56428 - iLabClient 本地数据库明文存储凭据  
**类型:** 信息泄露  
**风险:** 中危，本地数据库明文存储密码，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-05-21  
**POC仓库:** [CVE-2024-56428](https://github.com/lisa-2905/CVE-2024-56428)  

---

### [CVE-2020-10199](CVE-2020-10199-wsfengfan_CVE-2020-10199-10204.md) 🔴 ✅

**名称:** CVE-2020-10199-Sonatype Nexus Repository-JavaEL Injection  
**类型:** JavaEL Injection  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-05-21  
**POC仓库:** [CVE-2020-10199-10204](https://github.com/wsfengfan/CVE-2020-10199-10204)  

---

### [CVE-2020-10199](CVE-2020-10199-jas502n_CVE-2020-10199.md) 🔴 ✅

**名称:** CVE-2020-10199-Sonatype Nexus Repository-JavaEL注入导致远程代码执行  
**类型:** JavaEL注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-05-21  
**POC仓库:** [CVE-2020-10199](https://github.com/jas502n/CVE-2020-10199)  

---

### [CVE-2020-10199](CVE-2020-10199-magicming200_CVE-2020-10199_CVE-2020-10204.md) 🔴 ✅

**名称:** CVE-2020-10199-Sonatype Nexus Repository-JavaEL注入  
**类型:** JavaEL注入  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-05-21  
**POC仓库:** [CVE-2020-10199_CVE-2020-10204](https://github.com/magicming200/CVE-2020-10199_CVE-2020-10204)  

---

### [CVE-2020-10199](CVE-2020-10199-aleenzz_CVE-2020-10199.md) 🔴 ✅

**名称:** CVE-2020-10199-Sonatype Nexus Repository-JavaEL注入  
**类型:** JavaEL注入  
**风险:** 高危，可远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-05-21  
**POC仓库:** [CVE-2020-10199](https://github.com/aleenzz/CVE-2020-10199)  

---

### [CVE-2020-10199](CVE-2020-10199-zhzyker_CVE-2020-10199_POC-EXP.md) 🔴 ✅

**名称:** CVE-2020-10199-Sonatype Nexus Repository-JavaEL注入  
**类型:** JavaEL注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-05-21  
**POC仓库:** [CVE-2020-10199_POC-EXP](https://github.com/zhzyker/CVE-2020-10199_POC-EXP)  

---

### [CVE-2020-10199](CVE-2020-10199-hugosg97_CVE-2020-10199-Nexus-3.21.01.md) 🔴 ✅

**名称:** CVE-2020-10199-Sonatype Nexus Repository-JavaEL注入  
**类型:** JavaEL注入  
**风险:** 高危，允许远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-05-21  
**POC仓库:** [CVE-2020-10199-Nexus-3.21.01](https://github.com/hugosg97/CVE-2020-10199-Nexus-3.21.01)  

---

### [CVE-2020-10199](CVE-2020-10199-finn79426_CVE-2020-10199.md) 🔴 ✅

**名称:** CVE-2020-10199-Sonatype Nexus Repository-JavaEL注入  
**类型:** JavaEL注入  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-05-21  
**POC仓库:** [CVE-2020-10199](https://github.com/finn79426/CVE-2020-10199)  

---

### [CVE-2025-4524](CVE-2025-4524-ptrstr_CVE-2025-4524.md) 🔴 ✅

**名称:** CVE-2025-4524 - Madara-core WordPress theme 未授权本地文件包含 (LFI)  
**类型:** 本地文件包含 (LFI)  
**风险:** 高危，可能导致敏感信息泄露和远程代码执行（取决于服务器配置）  
**投毒风险:** 0%  
**发现时间:** 2025-05-20  
**POC仓库:** [CVE-2025-4524](https://github.com/ptrstr/CVE-2025-4524)  

---

### [CVE-2025-24085](CVE-2025-24085-pxx917144686_12345.md) 🔴 ✅

**名称:** CVE-2025-24085 - XNU内核压缩内存子系统权限绕过漏洞  
**类型:** Use-After-Free (释放后使用)  
**风险:** 高危，权限提升  
**投毒风险:** 10%  
**发现时间:** 2025-05-20  
**POC仓库:** [12345](https://github.com/pxx917144686/12345)  

---

### [CVE-2025-24085](CVE-2025-24085-windz3r0day_CVE-2025-24085.md) 🔴 

**名称:** CVE-2025-24085-Apple-Use-After-Free  
**类型:** Use-After-Free  
**风险:** 高危，可能导致权限提升  
**投毒风险:** 0%  
**发现时间:** 2025-05-20  
**POC仓库:** [CVE-2025-24085](https://github.com/windz3r0day/CVE-2025-24085)  

---

### [CVE-2025-40634](CVE-2025-40634-hacefresko_CVE-2025-40634.md) 🔴 ✅

**名称:** CVE-2025-40634 - TP-Link Archer AX50 栈溢出  
**类型:** 栈溢出  
**风险:** 高危，允许远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-05-20  
**POC仓库:** [CVE-2025-40634](https://github.com/hacefresko/CVE-2025-40634)  

---

### [CVE-2025-46801](CVE-2025-46801-Sratet_CVE-2025-46801.md) 🔴 ✅

**名称:** CVE-2025-46801 – Pgpool-II Authentication Bypass  
**类型:** 身份验证绕过  
**风险:** 高危，可能导致未授权的数据访问、篡改或拒绝服务  
**投毒风险:** 60%  
**发现时间:** 2025-05-20  
**POC仓库:** [CVE-2025-46801](https://github.com/Sratet/CVE-2025-46801)  

---

### [CVE-2025-4918](CVE-2025-4918-Totunm_CVE-2025-4918.md) 🔴 ✅

**名称:** CVE-2025-4918 - Firefox Promise对象越界读写  
**类型:** 内存破坏/越界读写  
**风险:** 高危，可导致远程代码执行或应用崩溃  
**投毒风险:** 10%  
**发现时间:** 2025-05-20  
**POC仓库:** [CVE-2025-4918](https://github.com/Totunm/CVE-2025-4918)  

---

### [CVE-2024-3094](CVE-2024-3094-laxmikumari615_Linux---Security---Detect-and-Mitigate-CVE-2024-3094.md)  ✅

**名称:** CVE-2024-3094 - XZ Utils供应链后门  
**类型:** 供应链攻击/后门  
**风险:** 极危，可能导致未经授权的远程SSH访问和任意代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-05-20  
**POC仓库:** [Linux---Security---Detect-and-Mitigate-CVE-2024-3094](https://github.com/laxmikumari615/Linux---Security---Detect-and-Mitigate-CVE-2024-3094)  

---

### [CVE-2025-4918](CVE-2025-4918-cyruscostini_CVE-2025-4918-RCE.md) 🔴 ✅

**名称:** CVE-2025-4918-Firefox-JavaScript Promise对象越界读写  
**类型:** 内存破坏  
**风险:** 高危，可能导致远程代码执行和应用程序崩溃  
**投毒风险:** 10%  
**发现时间:** 2025-05-20  
**POC仓库:** [CVE-2025-4918-RCE](https://github.com/cyruscostini/CVE-2025-4918-RCE)  

---

### [CVE-2025-47646](CVE-2025-47646-RootHarpy_CVE-2025-47646.md) 🔴 ✅

**名称:** CVE-2025-47646 - WordPress PSW Front-end Login Registration Plugin Unauthenticated Privilege Escalation  
**类型:** 权限提升  
**风险:** 高危，未授权用户可以创建管理员账户  
**投毒风险:** 10%  
**发现时间:** 2025-05-20  
**POC仓库:** [CVE-2025-47646](https://github.com/RootHarpy/CVE-2025-47646)  

---

### [CVE-2024-53677](CVE-2024-53677-WhoisBulud_CVE-2024-53677.md) 🔴 ✅

**名称:** CVE-2024-53677-Apache Struts 文件上传路径穿越RCE  
**类型:** 文件上传路径穿越导致远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-05-20  
**POC仓库:** [CVE-2024-53677](https://github.com/WhoisBulud/CVE-2024-53677)  

---

### [CVE-2025-4322](CVE-2025-4322-IndominusRexes_CVE-2025-4322-Exploit.md) 🔴 ✅

**名称:** CVE-2025-4322 - Motors WordPress Theme Unauthenticated Privilege Escalation  
**类型:** 权限提升/账户接管  
**风险:** 高危，可能导致站点完全控制  
**投毒风险:** 80%  
**发现时间:** 2025-05-20  
**POC仓库:** [CVE-2025-4322-Exploit](https://github.com/IndominusRexes/CVE-2025-4322-Exploit)  

---

### [CVE-2024-53677](CVE-2024-53677-c4oocO_CVE-2024-53677-Docker.md) 🔴 ✅

**名称:** CVE-2024-53677-Apache Struts文件上传路径穿越导致RCE  
**类型:** 文件上传路径穿越导致远程代码执行  
**风险:** 高危，可能导致远程代码执行和服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-05-20  
**POC仓库:** [CVE-2024-53677-Docker](https://github.com/c4oocO/CVE-2024-53677-Docker)  

---

### [CVE-2024-53677](CVE-2024-53677-yangyanglo_CVE-2024-53677.md) 🔴 ✅

**名称:** CVE-2024-53677-Apache Struts 文件上传路径遍历导致RCE  
**类型:** 文件上传路径遍历  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-05-20  
**POC仓库:** [CVE-2024-53677](https://github.com/yangyanglo/CVE-2024-53677)  

---

### [CVE-2024-53677](CVE-2024-53677-cloudwafs_s2-067-CVE-2024-53677.md) 🔴 ✅

**名称:** CVE-2024-53677-Apache Struts 文件上传路径穿越导致RCE  
**类型:** 文件上传路径穿越/远程代码执行  
**风险:** 高危，可导致服务器被完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-05-20  
**POC仓库:** [s2-067-CVE-2024-53677](https://github.com/cloudwafs/s2-067-CVE-2024-53677)  

---

### [CVE-2024-53677](CVE-2024-53677-XiaomingX_CVE-2024-53677-S2-067.md) 🔴 ✅

**名称:** CVE-2024-53677-Apache Struts 文件上传路径遍历导致RCE  
**类型:** 文件上传路径遍历导致远程代码执行  
**风险:** 高危，可能导致远程代码执行和服务器完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-05-20  
**POC仓库:** [CVE-2024-53677-S2-067](https://github.com/XiaomingX/CVE-2024-53677-S2-067)  

---

### [CVE-2024-53677](CVE-2024-53677-dustblessnotdust_CVE-2024-53677-S2-067-thread.md) 🔴 ✅

**名称:** CVE-2024-53677-Apache Struts文件上传路径遍历RCE  
**类型:** 文件上传路径遍历导致远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 1%  
**发现时间:** 2025-05-20  
**POC仓库:** [CVE-2024-53677-S2-067-thread](https://github.com/dustblessnotdust/CVE-2024-53677-S2-067-thread)  

---

### [CVE-2024-53677](CVE-2024-53677-TAM-K592_CVE-2024-53677-S2-067.md) 🔴 ✅

**名称:** CVE-2024-53677-Apache Struts文件上传路径遍历/RCE  
**类型:** 文件上传路径遍历/远程代码执行  
**风险:** 高危，可能导致远程代码执行和服务器完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-05-20  
**POC仓库:** [CVE-2024-53677-S2-067](https://github.com/TAM-K592/CVE-2024-53677-S2-067)  

---

### [CVE-2024-53677](CVE-2024-53677-0xdeviner_CVE-2024-53677.md) 🔴 ✅

**名称:** CVE-2024-53677 - Apache Struts文件上传路径穿越导致RCE  
**类型:** 文件上传路径穿越/远程代码执行  
**风险:** 高危，可导致任意文件上传和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-05-20  
**POC仓库:** [CVE-2024-53677](https://github.com/0xdeviner/CVE-2024-53677)  

---

### [CVE-2024-53677](CVE-2024-53677-EQSTLab_CVE-2024-53677.md) 🔴 ✅

**名称:** CVE-2024-53677 - Apache Struts 文件上传漏洞  
**类型:** 文件上传/路径遍历/远程代码执行  
**风险:** 高危，可导致远程代码执行和服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-05-20  
**POC仓库:** [CVE-2024-53677](https://github.com/EQSTLab/CVE-2024-53677)  

---

### [CVE-2024-53677](CVE-2024-53677-0xPThree_struts_cve-2024-53677.md) 🔴 ✅

**名称:** CVE-2024-53677-Apache Struts 文件上传路径遍历导致RCE  
**类型:** 文件上传路径遍历/远程代码执行  
**风险:** 高危，可能导致远程代码执行和服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-05-20  
**POC仓库:** [struts_cve-2024-53677](https://github.com/0xPThree/struts_cve-2024-53677)  

---

### [CVE-2024-53677](CVE-2024-53677-punitdarji_Apache-struts-cve-2024-53677.md) 🔴 ✅

**名称:** CVE-2024-53677-Apache Struts 文件上传漏洞  
**类型:** 文件上传/路径遍历/远程代码执行  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-05-20  
**POC仓库:** [Apache-struts-cve-2024-53677](https://github.com/punitdarji/Apache-struts-cve-2024-53677)  

---

### [CVE-2024-53677](CVE-2024-53677-hopsypopsy8_CVE-2024-53677-Exploitation.md) 🔴 ✅

**名称:** CVE-2024-53677-Apache Struts文件上传RCE  
**类型:** 远程代码执行（RCE）  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-05-20  
**POC仓库:** [CVE-2024-53677-Exploitation](https://github.com/hopsypopsy8/CVE-2024-53677-Exploitation)  

---

### [CVE-2024-53677](CVE-2024-53677-shishirghimir_CVE-2024-53677-Exploit.md) 🔴 ✅

**名称:** CVE-2024-53677-Apache Struts 文件上传路径穿越 RCE  
**类型:** 文件上传路径穿越导致远程代码执行  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-05-20  
**POC仓库:** [CVE-2024-53677-Exploit](https://github.com/shishirghimir/CVE-2024-53677-Exploit)  

---

### [CVE-2024-53677](CVE-2024-53677-SeanRickerd_CVE-2024-53677.md) 🔴 ✅

**名称:** CVE-2024-53677 - Apache Struts 文件上传路径遍历导致远程代码执行  
**类型:** 文件上传路径遍历/远程代码执行  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-05-20  
**POC仓库:** [CVE-2024-53677](https://github.com/SeanRickerd/CVE-2024-53677)  

---

### [CVE-2021-38003](CVE-2021-38003-SpiralBL0CK_Chrome-V8-RCE-CVE-2021-38003.md) 🔴 ✅

**名称:** CVE-2021-38003 - Chrome V8 堆损坏  
**类型:** 堆损坏  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 2%  
**发现时间:** 2025-05-20  
**POC仓库:** [Chrome-V8-RCE-CVE-2021-38003](https://github.com/SpiralBL0CK/Chrome-V8-RCE-CVE-2021-38003)  

---

### [CVE-2021-38003](CVE-2021-38003-caffeinedoom_CVE-2021-38003.md) 🔴 ✅

**名称:** CVE-2021-38003 - Chrome V8 堆损坏  
**类型:** 堆损坏  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-05-20  
**POC仓库:** [CVE-2021-38003](https://github.com/caffeinedoom/CVE-2021-38003)  

---

### [CVE-2024-4577](CVE-2024-4577-shockingbonu_CVE-2024-4577-PHP-RCE.md) 🔴 ✅

**名称:** CVE-2024-4577-PHP-CGI Argument Injection  
**类型:** OS Command Injection  
**风险:** Critical，可能导致远程代码执行  
**投毒风险:** 99%  
**发现时间:** 2025-05-19  
**POC仓库:** [CVE-2024-4577-PHP-RCE](https://github.com/shockingbonu/CVE-2024-4577-PHP-RCE)  

---

### [CVE-2025-1974](CVE-2025-1974-Rickerd12_exploit-cve-2025-1974.md) 🔴 ✅

**名称:** CVE-2025-1974-ingress-nginx-RCE  
**类型:** 远程代码执行(RCE)  
**风险:** 高危，可能导致集群范围内的 Secrets 泄露和任意代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-05-19  
**POC仓库:** [exploit-cve-2025-1974](https://github.com/Rickerd12/exploit-cve-2025-1974)  

---

### [CVE-2025-24054](CVE-2025-24054-moften_CVE-2025-24054.md) 🟡 ✅

**名称:** CVE-2025-24054-NTLM Hash Disclosure Spoofing Vulnerability  
**类型:** NTLM Hash Disclosure Spoofing  
**风险:** 中危，可能导致身份冒充和权限提升  
**投毒风险:** 0%  
**发现时间:** 2025-05-19  
**POC仓库:** [CVE-2025-24054](https://github.com/moften/CVE-2025-24054)  

---

### [CVE-2025-4919](CVE-2025-4919-HExploited_CVE-2025-4919-Exploit.md) 🔴 

**名称:** CVE-2025-4919-Firefox JavaScript OOB R/W  
**类型:** Out-of-Bounds Read/Write  
**风险:** 高危，可能导致任意代码执行、信息泄露和拒绝服务  
**投毒风险:** 85%  
**发现时间:** 2025-05-19  
**POC仓库:** [CVE-2025-4919-Exploit](https://github.com/HExploited/CVE-2025-4919-Exploit)  

---

### [CVE-2019-9978](CVE-2019-9978-Housma_CVE-2019-9978-Social-Warfare-WordPress-Plugin-RCE.md) 🔴 ✅

**名称:** CVE-2019-9978 - Social Warfare WordPress Plugin RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 1%  
**发现时间:** 2025-05-19  
**POC仓库:** [CVE-2019-9978-Social-Warfare-WordPress-Plugin-RCE](https://github.com/Housma/CVE-2019-9978-Social-Warfare-WordPress-Plugin-RCE)  

---

### [CVE-2025-29813](CVE-2025-29813-Sratet_CVE-2025-29813-PE.md)  ✅

**名称:** CVE-2025-29813-Azure DevOps Server-权限提升  
**类型:** 权限提升  
**风险:** 严重，可能导致完全控制DevOps环境  
**投毒风险:** 75%  
**发现时间:** 2025-05-19  
**POC仓库:** [CVE-2025-29813-PE](https://github.com/Sratet/CVE-2025-29813-PE)  

---

### [CVE-2021-43798](CVE-2021-43798-rnsss_CVE-2021-43798-poc.md) 🔴 ✅

**名称:** CVE-2021-43798-Grafana目录遍历  
**类型:** 目录遍历  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-05-19  
**POC仓库:** [CVE-2021-43798-poc](https://github.com/rnsss/CVE-2021-43798-poc)  

---

### [CVE-2021-43798](CVE-2021-43798-rodpwn_CVE-2021-43798-mass_scanner.md) 🔴 ✅

**名称:** CVE-2021-43798 - Grafana Directory Traversal  
**类型:** 目录遍历  
**风险:** 高危，允许未经授权的本地文件读取  
**投毒风险:** 20%  
**发现时间:** 2025-05-19  
**POC仓库:** [CVE-2021-43798-mass_scanner](https://github.com/rodpwn/CVE-2021-43798-mass_scanner)  

---

### [CVE-2021-43798](CVE-2021-43798-Bouquets-ai_CVE-2021-43798.md) 🔴 ✅

**名称:** CVE-2021-43798-Grafana-目录遍历  
**类型:** 目录遍历  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-05-19  
**POC仓库:** [CVE-2021-43798](https://github.com/Bouquets-ai/CVE-2021-43798)  

---

### [CVE-2021-43798](CVE-2021-43798-aymenbouferroum_CVE-2021-43798_exploit.md) 🔴 ✅

**名称:** CVE-2021-43798 Grafana 目录遍历  
**类型:** 目录遍历  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-05-19  
**POC仓库:** [CVE-2021-43798_exploit](https://github.com/aymenbouferroum/CVE-2021-43798_exploit)  

---

### [CVE-2021-43798](CVE-2021-43798-M0ge_CVE-2021-43798-grafana_fileread.md) 🔴 ✅

**名称:** CVE-2021-43798-Grafana-目录遍历  
**类型:** 目录遍历  
**风险:** 高危，可读取敏感文件  
**投毒风险:** 1%  
**发现时间:** 2025-05-19  
**POC仓库:** [CVE-2021-43798-grafana_fileread](https://github.com/M0ge/CVE-2021-43798-grafana_fileread)  

---

### [CVE-2021-43798](CVE-2021-43798-yasindce1998_grafana-cve-2021-43798.md) 🔴 ✅

**名称:** CVE-2021-43798-Grafana-目录遍历  
**类型:** 目录遍历  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-05-19  
**POC仓库:** [grafana-cve-2021-43798](https://github.com/yasindce1998/grafana-cve-2021-43798)  

---

### [CVE-2021-43798](CVE-2021-43798-k3rwin_CVE-2021-43798-Grafana.md) 🔴 ✅

**名称:** CVE-2021-43798 Grafana 目录遍历/任意文件读取  
**类型:** 目录遍历/任意文件读取  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-05-19  
**POC仓库:** [CVE-2021-43798-Grafana](https://github.com/k3rwin/CVE-2021-43798-Grafana)  

---

### [CVE-2021-43798](CVE-2021-43798-Jroo1053_GrafanaDirInclusion.md) 🔴 ✅

**名称:** CVE-2021-43798 - Grafana Directory Traversal  
**类型:** 目录遍历  
**风险:** 高危，可能导致敏感文件泄露  
**投毒风险:** 0%  
**发现时间:** 2025-05-19  
**POC仓库:** [GrafanaDirInclusion](https://github.com/Jroo1053/GrafanaDirInclusion)  

---

### [CVE-2021-43798](CVE-2021-43798-hupe1980_CVE-2021-43798.md) 🔴 ✅

**名称:** CVE-2021-43798-Grafana-目录遍历  
**类型:** 目录遍历  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-05-19  
**POC仓库:** [CVE-2021-43798](https://github.com/hupe1980/CVE-2021-43798)  

---

### [CVE-2021-43798](CVE-2021-43798-G01d3nW01f_CVE-2021-43798.md) 🔴 ✅

**名称:** CVE-2021-43798-Grafana-目录遍历  
**类型:** 目录遍历  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-05-19  
**POC仓库:** [CVE-2021-43798](https://github.com/G01d3nW01f/CVE-2021-43798)  

---

### [CVE-2021-43798](CVE-2021-43798-mauricelambert_LabAutomationCVE-2021-43798.md) 🔴 ✅

**名称:** CVE-2021-43798-Grafana-目录遍历  
**类型:** 目录遍历  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-05-19  
**POC仓库:** [LabAutomationCVE-2021-43798](https://github.com/mauricelambert/LabAutomationCVE-2021-43798)  

---

### [CVE-2021-43798](CVE-2021-43798-jas502n_Grafana-CVE-2021-43798.md) 🔴 ✅

**名称:** CVE-2021-43798-Grafana-目录遍历  
**类型:** 目录遍历  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-05-19  
**POC仓库:** [Grafana-CVE-2021-43798](https://github.com/jas502n/Grafana-CVE-2021-43798)  

---

### [CVE-2021-43798](CVE-2021-43798-FAOG99_GrafanaDirectoryScanner.md) 🔴 ✅

**名称:** CVE-2021-43798-Grafana目录遍历  
**类型:** 目录遍历  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-05-19  
**POC仓库:** [GrafanaDirectoryScanner](https://github.com/FAOG99/GrafanaDirectoryScanner)  

---

### [CVE-2021-43798](CVE-2021-43798-victorhorowitz_grafana-exploit-CVE-2021-43798.md) 🔴 ✅

**名称:** CVE-2021-43798-Grafana-目录遍历  
**类型:** 目录遍历  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-05-19  
**POC仓库:** [grafana-exploit-CVE-2021-43798](https://github.com/victorhorowitz/grafana-exploit-CVE-2021-43798)  

---

### [CVE-2021-43798](CVE-2021-43798-katseyres2_CVE-2021-43798.md) 🔴 ✅

**名称:** CVE-2021-43798-Grafana-目录遍历  
**类型:** 目录遍历  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-05-19  
**POC仓库:** [CVE-2021-43798](https://github.com/katseyres2/CVE-2021-43798)  

---

### [CVE-2021-43798](CVE-2021-43798-Iris288_CVE-2021-43798.md) 🔴 ✅

**名称:** CVE-2021-43798-Grafana-目录遍历  
**类型:** 目录遍历  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-05-19  
**POC仓库:** [CVE-2021-43798](https://github.com/Iris288/CVE-2021-43798)  

---

### [CVE-2021-43798](CVE-2021-43798-wagneralves_CVE-2021-43798.md) 🔴 ✅

**名称:** CVE-2021-43798-Grafana-目录遍历  
**类型:** 目录遍历  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-05-19  
**POC仓库:** [CVE-2021-43798](https://github.com/wagneralves/CVE-2021-43798)  

---

### [CVE-2021-43798](CVE-2021-43798-K3ysTr0K3R_CVE-2021-43798-EXPLOIT.md) 🔴 ✅

**名称:** CVE-2021-43798-Grafana-目录遍历  
**类型:** 目录遍历  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 1%  
**发现时间:** 2025-05-19  
**POC仓库:** [CVE-2021-43798-EXPLOIT](https://github.com/K3ysTr0K3R/CVE-2021-43798-EXPLOIT)  

---

### [CVE-2021-43798](CVE-2021-43798-ticofookfook_CVE-2021-43798.md) 🔴 ✅

**名称:** CVE-2021-43798-Grafana-目录遍历  
**类型:** 目录遍历  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-05-19  
**POC仓库:** [CVE-2021-43798](https://github.com/ticofookfook/CVE-2021-43798)  

---

### [CVE-2021-43798](CVE-2021-43798-MalekAlthubiany_CVE-2021-43798.md) 🔴 ✅

**名称:** CVE-2021-43798-Grafana目录遍历  
**类型:** 目录遍历  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-05-19  
**POC仓库:** [CVE-2021-43798](https://github.com/MalekAlthubiany/CVE-2021-43798)  

---

### [CVE-2021-43798](CVE-2021-43798-Sic4rio_Grafana-Decryptor-for-CVE-2021-43798.md) 🔴 ✅

**名称:** CVE-2021-43798-Grafana-目录遍历  
**类型:** 目录遍历  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 5%  
**发现时间:** 2025-05-19  
**POC仓库:** [Grafana-Decryptor-for-CVE-2021-43798](https://github.com/Sic4rio/Grafana-Decryptor-for-CVE-2021-43798)  

---

### [CVE-2021-43798](CVE-2021-43798-A-D-Team_grafanaExp.md) 🔴 ✅

**名称:** CVE-2021-43798 Grafana 目录遍历漏洞  
**类型:** 目录遍历  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 5%  
**发现时间:** 2025-05-19  
**POC仓库:** [grafanaExp](https://github.com/A-D-Team/grafanaExp)  

---

### [CVE-2021-43798](CVE-2021-43798-0xSAZZAD_Grafana-CVE-2021-43798.md) 🔴 ✅

**名称:** CVE-2021-43798 - Grafana 目录遍历和密码解密  
**类型:** 目录遍历/密码解密  
**风险:** 高危，允许任意文件读取和敏感信息泄露  
**投毒风险:** 5%  
**发现时间:** 2025-05-19  
**POC仓库:** [Grafana-CVE-2021-43798](https://github.com/0xSAZZAD/Grafana-CVE-2021-43798)  

---

### [CVE-2021-43798](CVE-2021-43798-wezoomagency_GrafXploit.md) 🔴 ✅

**名称:** CVE-2021-43798-Grafana-目录遍历  
**类型:** 目录遍历  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-05-19  
**POC仓库:** [GrafXploit](https://github.com/wezoomagency/GrafXploit)  

---

### [CVE-2021-43798](CVE-2021-43798-davidr-io_Grafana-8.3-Directory-Traversal.md) 🔴 ✅

**名称:** CVE-2021-43798-Grafana-目录遍历  
**类型:** 目录遍历  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-05-19  
**POC仓库:** [Grafana-8.3-Directory-Traversal](https://github.com/davidr-io/Grafana-8.3-Directory-Traversal)  

---

### [CVE-2021-43798](CVE-2021-43798-ravi5hanka_CVE-2021-43798-Exploit-for-Windows-and-Linux.md) 🔴 ✅

**名称:** CVE-2021-43798 - Grafana 目录遍历漏洞  
**类型:** 目录遍历  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 5%  
**发现时间:** 2025-05-19  
**POC仓库:** [CVE-2021-43798-Exploit-for-Windows-and-Linux](https://github.com/ravi5hanka/CVE-2021-43798-Exploit-for-Windows-and-Linux)  

---

### [CVE-2021-43798](CVE-2021-43798-monke443_CVE-2021-43798.md) 🔴 ✅

**名称:** CVE-2021-43798 Grafana目录遍历漏洞  
**类型:** 目录遍历  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-05-19  
**POC仓库:** [CVE-2021-43798](https://github.com/monke443/CVE-2021-43798)  

---

### [CVE-2021-43798](CVE-2021-43798-suljov_Grafana-LFI-exploit.md) 🔴 ✅

**名称:** CVE-2021-43798-Grafana-目录遍历  
**类型:** 目录遍历  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-05-19  
**POC仓库:** [Grafana-LFI-exploit](https://github.com/suljov/Grafana-LFI-exploit)  

---

### [CVE-2021-43798](CVE-2021-43798-abuyazeen_CVE-2021-43798-Grafana-path-traversal-tester.md) 🔴 ✅

**名称:** CVE-2021-43798 - Grafana 目录遍历  
**类型:** 目录遍历  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-05-19  
**POC仓库:** [CVE-2021-43798-Grafana-path-traversal-tester](https://github.com/abuyazeen/CVE-2021-43798-Grafana-path-traversal-tester)  

---

### [CVE-2011-0762](CVE-2011-0762-AndreyFreitax_CVE-2011-0762.md) 🟡 ✅

**名称:** CVE-2011-0762 - vsftpd STAT 命令拒绝服务  
**类型:** 拒绝服务 (DoS)  
**风险:** 中危，导致CPU资源耗尽和进程槽耗尽  
**投毒风险:** 0%  
**发现时间:** 2025-05-19  
**POC仓库:** [CVE-2011-0762](https://github.com/AndreyFreitax/CVE-2011-0762)  

---

### [CVE-2025-2135](CVE-2025-2135-Wa1nut4_CVE-2025-2135.md) 🔴 ✅

**名称:** CVE-2025-2135-Chrome-Type Confusion  
**类型:** 类型混淆  
**风险:** 高危，可能导致堆腐败和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-05-19  
**POC仓库:** [CVE-2025-2135](https://github.com/Wa1nut4/CVE-2025-2135)  

---

### [CVE-2018-16621](CVE-2018-16621-Loucy1231_Nexus-Repository-Manager3-EL-CVE-2018-16621-https-www.cve.org-CVERecord-id-CVE-2018-16621-.md) 🔴 ✅

**名称:** CVE-2018-16621-Nexus Repository Manager-Java表达式语言注入  
**类型:** Java表达式语言注入  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-05-19  
**POC仓库:** [Nexus-Repository-Manager3-EL-CVE-2018-16621-https-www.cve.org-CVERecord-id-CVE-2018-16621-](https://github.com/Loucy1231/Nexus-Repository-Manager3-EL-CVE-2018-16621-https-www.cve.org-CVERecord-id-CVE-2018-16621-)  

---

### [CVE-2025-4428](CVE-2025-4428-doomygloom_CVE-2025-4428.md) 🔴 

**名称:** CVE-2025-4428 - Ivanti EPMM 远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，允许攻击者在受影响的系统上执行任意代码。  
**投毒风险:** 10%  
**发现时间:** 2025-05-18  
**POC仓库:** [CVE-2025-4428](https://github.com/doomygloom/CVE-2025-4428)  

---

### [CVE-2025-24104](CVE-2025-24104-ifpdz_CVE-2025-24104.md) 🟡 ✅

**名称:** CVE-2025-24104-iOS/iPadOS备份文件符号链接读取漏洞  
**类型:** 符号链接  
**风险:** 中危，可能导致敏感数据泄露  
**投毒风险:** 10%  
**发现时间:** 2025-05-18  
**POC仓库:** [CVE-2025-24104](https://github.com/ifpdz/CVE-2025-24104)  

---

### [CVE-2025-24104](CVE-2025-24104-missaels235_POC-CVE-2025-24104-Py.md) 🟡 ✅

**名称:** CVE-2025-24104 - iOS/iPadOS 本地文件修改漏洞  
**类型:** 符号链接处理不当导致的文件修改  
**风险:** 中危，需要用户交互，可能导致受保护的系统文件被修改  
**投毒风险:** 10%  
**发现时间:** 2025-05-18  
**POC仓库:** [POC-CVE-2025-24104-Py](https://github.com/missaels235/POC-CVE-2025-24104-Py)  

---

### [CVE-2025-32756](CVE-2025-32756-exfil0_CVE-2025-32756-POC.md) 🔴 

**名称:** CVE-2025-32756-多个Fortinet产品栈溢出  
**类型:** 栈溢出  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-05-18  
**POC仓库:** [CVE-2025-32756-POC](https://github.com/exfil0/CVE-2025-32756-POC)  

---

### [CVE-2024-41713](CVE-2024-41713-watchtowrlabs_Mitel-MiCollab-Auth-Bypass_CVE-2024-41713.md) 🔴 ✅

**名称:** CVE-2024-41713 - Mitel MiCollab 路径遍历  
**类型:** 路径遍历  
**风险:** 高危，可能导致未授权访问，数据泄露和系统配置篡改  
**投毒风险:** 0%  
**发现时间:** 2025-05-18  
**POC仓库:** [Mitel-MiCollab-Auth-Bypass_CVE-2024-41713](https://github.com/watchtowrlabs/Mitel-MiCollab-Auth-Bypass_CVE-2024-41713)  

---

### [CVE-2024-41713](CVE-2024-41713-zxj-hub_CVE-2024-41713POC.md) 🔴 ✅

**名称:** CVE-2024-41713 - Mitel MiCollab 任意文件读取漏洞  
**类型:** 路径遍历  
**风险:** 高危，可能导致未授权访问、数据泄露、数据破坏和系统配置篡改  
**投毒风险:** 0%  
**发现时间:** 2025-05-18  
**POC仓库:** [CVE-2024-41713POC](https://github.com/zxj-hub/CVE-2024-41713POC)  

---

### [CVE-2024-41713](CVE-2024-41713-Sanandd_cve-2024-CVE-2024-41713.md) 🔴 ✅

**名称:** CVE-2024-41713-Mitel MiCollab-路径遍历  
**类型:** 路径遍历  
**风险:** 高危，未授权访问，可能导致数据泄露、篡改或删除用户数据和系统配置  
**投毒风险:** 0%  
**发现时间:** 2025-05-18  
**POC仓库:** [cve-2024-CVE-2024-41713](https://github.com/Sanandd/cve-2024-CVE-2024-41713)  

---

### [CVE-2024-41713](CVE-2024-41713-amanverma-wsu_CVE-2024-41713-Scan.md) 🔴 ✅

**名称:** CVE-2024-41713 - Mitel MiCollab 路径遍历漏洞  
**类型:** 路径遍历  
**风险:** 高危，可能导致未授权访问，数据泄露，配置篡改  
**投毒风险:** 5%  
**发现时间:** 2025-05-18  
**POC仓库:** [CVE-2024-41713-Scan](https://github.com/amanverma-wsu/CVE-2024-41713-Scan)  

---

### [CVE-2024-41713](CVE-2024-41713-gunyakit_CVE-2024-41713-PoC-exploit.md) 🔴 ✅

**名称:** CVE-2024-41713-Mitel MiCollab-路径遍历  
**类型:** 路径遍历  
**风险:** 高危，可能导致敏感信息泄露和系统配置被篡改。  
**投毒风险:** 10%  
**发现时间:** 2025-05-18  
**POC仓库:** [CVE-2024-41713-PoC-exploit](https://github.com/gunyakit/CVE-2024-41713-PoC-exploit)  

---

### [CVE-2025-4921](CVE-2025-4921-doomygloom_CVE-2025-4921.md) 🔴 

**名称:** CVE-2025-4921-Firefox-Out-of-bounds访问  
**类型:** Out-of-bounds Read/Write  
**风险:** 高危，可能导致信息泄露或任意代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-05-18  
**POC仓库:** [CVE-2025-4921](https://github.com/doomygloom/CVE-2025-4921)  

---

### [CVE-2024-44258](CVE-2024-44258-ifpdz_CVE-2024-44258.md) 🔴 ✅

**名称:** CVE-2024-44258 - Apple 设备 ManagedConfiguration 框架 Symlink 漏洞  
**类型:** 符号链接（Symlink）漏洞  
**风险:** 高危，可能导致修改受保护的系统文件  
**投毒风险:** 10%  
**发现时间:** 2025-05-18  
**POC仓库:** [CVE-2024-44258](https://github.com/ifpdz/CVE-2024-44258)  

---

### [CVE-2024-44258](CVE-2024-44258-missaels235_POC-CVE-2024-44258-Py.md) 🔴 

**名称:** CVE-2024-44258-iOS备份恢复Symlink漏洞  
**类型:** Symlink漏洞  
**风险:** 高危，可能导致修改受保护的系统文件  
**投毒风险:** 10%  
**发现时间:** 2025-05-18  
**POC仓库:** [POC-CVE-2024-44258-Py](https://github.com/missaels235/POC-CVE-2024-44258-Py)  

---

### [CVE-2025-4664](CVE-2025-4664-doomygloom_CVE-2025-4664.md) 🟡 ✅

**名称:** CVE-2025-4664  
**类型:** 跨域数据泄露  
**风险:** 中危，可能导致敏感信息泄露  
**投毒风险:** 99%  
**发现时间:** 2025-05-18  
**POC仓库:** [CVE-2025-4664](https://github.com/doomygloom/CVE-2025-4664)  

---

### [CVE-2025-32259](CVE-2025-32259-HossamEAhmed_wp-ulike-cve-2025-32259-poc.md) 🟡 ✅

**名称:** CVE-2025-32259-WP ULike-内容欺骗漏洞  
**类型:** 内容欺骗  
**风险:** 中危，可能导致内容被篡改，影响用户信任  
**投毒风险:** 0%  
**发现时间:** 2025-05-18  
**POC仓库:** [wp-ulike-cve-2025-32259-poc](https://github.com/HossamEAhmed/wp-ulike-cve-2025-32259-poc)  

---

### [CVE-2025-31200](CVE-2025-31200-zhuowei_apple-positional-audio-codec-invalid-header.md) 🔴 

**名称:** CVE-2025-31200-CoreAudio-内存损坏  
**类型:** 内存损坏  
**风险:** 高危，可能导致代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-05-17  
**POC仓库:** [apple-positional-audio-codec-invalid-header](https://github.com/zhuowei/apple-positional-audio-codec-invalid-header)  

---

### [CVE-2025-31200](CVE-2025-31200-JGoyd_CVE-2025-31200-iOS-AudioConverter-RCE.md) 🔴 ✅

**名称:** CVE-2025-31200-iOS-AudioConverter-RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，允许远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-05-17  
**POC仓库:** [CVE-2025-31200-iOS-AudioConverter-RCE](https://github.com/JGoyd/CVE-2025-31200-iOS-AudioConverter-RCE)  

---

### [CVE-2025-47539](CVE-2025-47539-Nxploited_CVE-2025-47539.md) 🔴 ✅

**名称:** CVE-2025-47539 - WordPress Eventin 插件权限提升  
**类型:** 权限提升  
**风险:** 高危，允许未授权的攻击者创建管理员账户  
**投毒风险:** 0%  
**发现时间:** 2025-05-17  
**POC仓库:** [CVE-2025-47539](https://github.com/Nxploited/CVE-2025-47539)  

---

### [CVE-2025-12654](CVE-2025-12654-Taonauz_Anydesk-Exploit-CVE-2025-12654-RCE-Builder.md) 🔴 ✅

**名称:** CVE-2025-12654/CVE-2020-13160 - AnyDesk 远程代码执行/DLL劫持漏洞  
**类型:** 远程代码执行/DLL劫持  
**风险:** 高危，可能导致远程代码执行，系统完全控制  
**投毒风险:** 60%  
**发现时间:** 2025-05-17  
**POC仓库:** [Anydesk-Exploit-CVE-2025-12654-RCE-Builder](https://github.com/Taonauz/Anydesk-Exploit-CVE-2025-12654-RCE-Builder)  

---

### [CVE-2024-2887](CVE-2024-2887-PumpkinBridge_Chrome-CVE-2024-2887-RCE-POC.md) 🔴 ✅

**名称:** CVE-2024-2887 - Google Chrome WebAssembly 类型混淆漏洞  
**类型:** 类型混淆  
**风险:** 高危，允许远程攻击者通过特制的HTML页面执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-05-17  
**POC仓库:** [Chrome-CVE-2024-2887-RCE-POC](https://github.com/PumpkinBridge/Chrome-CVE-2024-2887-RCE-POC)  

---

### [CVE-2024-2887](CVE-2024-2887-rycbar77_CVE-2024-2887.md) 🔴 ✅

**名称:** CVE-2024-2887-Chrome-WebAssembly类型混淆  
**类型:** 类型混淆  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-05-17  
**POC仓库:** [CVE-2024-2887](https://github.com/rycbar77/CVE-2024-2887)  

---

### [CVE-2024-2887](CVE-2024-2887-jjyuorg_reproduce-cve-2024-2887.md) 🔴 ✅

**名称:** CVE-2024-2887-Google Chrome-WebAssembly类型混淆  
**类型:** 类型混淆  
**风险:** 高危，允许远程攻击者通过精心设计的HTML页面执行任意代码  
**投毒风险:** 0%  
**发现时间:** 2025-05-17  
**POC仓库:** [reproduce-cve-2024-2887](https://github.com/jjyuorg/reproduce-cve-2024-2887)  

---

### [CVE-2023-25813](CVE-2023-25813-platypus-perry03_CVE-2023-25813.md) 🔴 ✅

**名称:** CVE-2023-25813-Sequelize-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-05-17  
**POC仓库:** [CVE-2023-25813](https://github.com/platypus-perry03/CVE-2023-25813)  

---

### [CVE-2021-4034](CVE-2021-4034-kali-guru_Pwnkit-CVE-2021-4034.md) 🔴 ✅

**名称:** CVE-2021-4034-Polkit-pkexec 本地提权  
**类型:** 本地提权  
**风险:** 高危，允许低权限用户获取root权限  
**投毒风险:** 0%  
**发现时间:** 2025-05-17  
**POC仓库:** [Pwnkit-CVE-2021-4034](https://github.com/kali-guru/Pwnkit-CVE-2021-4034)  

---

### [CVE-2024-3661](CVE-2024-3661-Wh1t3Fox_CVE-2024-3661.md) 🔴 ✅

**名称:** CVE-2024-3661-VPN TunnelVision-DHCP路由劫持  
**类型:** DHCP路由劫持  
**风险:** 高危，可能导致VPN流量泄露，数据窃取，中间人攻击  
**投毒风险:** 5%  
**发现时间:** 2025-05-16  
**POC仓库:** [CVE-2024-3661](https://github.com/Wh1t3Fox/CVE-2024-3661)  

---

### [CVE-2025-4427](CVE-2025-4427-cdrom0_CVE-2025-4427.md) 🟡 ✅

**名称:** CVE-2025-4427-Ivanti EPMM-身份验证绕过  
**类型:** 身份验证绕过  
**风险:** 中危，可能导致未经授权的资源访问  
**投毒风险:** 100%  
**发现时间:** 2025-05-16  
**POC仓库:** [CVE-2025-4427](https://github.com/cdrom0/CVE-2025-4427)  

---

### [CVE-2017-7184](CVE-2017-7184-b1nhack_CVE-2017-7184.md) 🔴 ✅

**名称:** CVE-2017-7184-Linux Kernel-XFRM heap out-of-bounds access  
**类型:** Heap out-of-bounds access  
**风险:** 高危，可能导致本地提权或拒绝服务  
**投毒风险:** 0%  
**发现时间:** 2025-05-16  
**POC仓库:** [CVE-2017-7184](https://github.com/b1nhack/CVE-2017-7184)  

---

### [CVE-2024-3661](CVE-2024-3661-Wh1t3Fox_CVE-2024-3661.md) 🔴 ✅

**名称:** CVE-2024-3661 - TunnelVision VPN Bypass  
**类型:** VPN绕过  
**风险:** 高危，可能导致敏感数据泄露，流量被窃听或篡改  
**投毒风险:** 0%  
**发现时间:** 2025-05-16  
**POC仓库:** [CVE-2024-3661](https://github.com/Wh1t3Fox/CVE-2024-3661)  

---

### [CVE-2022-41082](CVE-2022-41082-sikkertech_CVE-2022-41082.md) 🔴 ✅

**名称:** CVE-2022-41082 - Microsoft Exchange Server 远程代码执行漏洞  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-05-16  
**POC仓库:** [CVE-2022-41082](https://github.com/sikkertech/CVE-2022-41082)  

---

### [CVE-2022-41082](CVE-2022-41082-Diverto_nse-exchange.md) 🔴 ✅

**名称:** CVE-2022-41082-Microsoft Exchange Server-RCE  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-05-16  
**POC仓库:** [nse-exchange](https://github.com/Diverto/nse-exchange)  

---

### [CVE-2022-41082](CVE-2022-41082-balki97_OWASSRF-CVE-2022-41082-POC.md) 🔴 ✅

**名称:** CVE-2022-41082 - Microsoft Exchange Server Remote Code Execution  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-05-16  
**POC仓库:** [OWASSRF-CVE-2022-41082-POC](https://github.com/balki97/OWASSRF-CVE-2022-41082-POC)  

---

### [CVE-2022-41082](CVE-2022-41082-bigherocenter_CVE-2022-41082-POC.md) 🔴 ✅

**名称:** CVE-2022-41082-Microsoft Exchange Server Remote Code Execution Vulnerability  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-05-16  
**POC仓库:** [CVE-2022-41082-POC](https://github.com/bigherocenter/CVE-2022-41082-POC)  

---

### [CVE-2022-41082](CVE-2022-41082-notareaperbutDR34P3r_vuln-CVE-2022-41082.md) 🔴 ✅

**名称:** CVE-2022-41082 Microsoft Exchange Server 远程代码执行漏洞  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-05-16  
**POC仓库:** [vuln-CVE-2022-41082](https://github.com/notareaperbutDR34P3r/vuln-CVE-2022-41082)  

---

### [CVE-2022-41082](CVE-2022-41082-notareaperbutDR34P3r_http-vuln-CVE-2022-41082.md) 🔴 ✅

**名称:** CVE-2022-41082-Microsoft Exchange Server Remote Code Execution  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-05-16  
**POC仓库:** [http-vuln-CVE-2022-41082](https://github.com/notareaperbutDR34P3r/http-vuln-CVE-2022-41082)  

---

### [CVE-2022-41082](CVE-2022-41082-SUPRAAA-1337_CVE-2022-41082.md) 🔴 ✅

**名称:** CVE-2022-41082-Microsoft Exchange Server Remote Code Execution  
**类型:** 远程代码执行  
**风险:** 高危，允许远程代码执行，可能导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-05-16  
**POC仓库:** [CVE-2022-41082](https://github.com/SUPRAAA-1337/CVE-2022-41082)  

---

### [CVE-2022-41082](CVE-2022-41082-soltanali0_CVE-2022-41082.md) 🔴 ✅

**名称:** CVE-2022-41082-Microsoft Exchange Server Remote Code Execution Vulnerability  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-05-16  
**POC仓库:** [CVE-2022-41082](https://github.com/soltanali0/CVE-2022-41082)  

---

### [CVE-2022-41082](CVE-2022-41082-CyprianAtsyor_LetsDefend-CVE-2022-41082-Exploitation-Attempt.md) 🔴 ✅

**名称:** CVE-2022-41082 Microsoft Exchange Server 远程代码执行漏洞  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，攻击者可以利用此漏洞在受影响的Exchange服务器上执行任意代码。  
**投毒风险:** 0%  
**发现时间:** 2025-05-16  
**POC仓库:** [LetsDefend-CVE-2022-41082-Exploitation-Attempt](https://github.com/CyprianAtsyor/LetsDefend-CVE-2022-41082-Exploitation-Attempt)  

---

### [CVE-2025-4822](CVE-2025-4822-sahici_CVE-2025-4822.md) 🔴 ✅

**名称:** CVE-2025-4822  
**类型:** 未知  
**风险:** 高危  
**投毒风险:** 10%  
**发现时间:** 2025-05-16  
**POC仓库:** [CVE-2025-4822](https://github.com/sahici/CVE-2025-4822)  

---

### [CVE-2025-32583](CVE-2025-32583-GadaLuBau1337_CVE-2025-32583.md) 🔴 ✅

**名称:** CVE-2025-32583-WordPress PDF 2 Post Plugin-RCE  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 1%  
**发现时间:** 2025-05-16  
**POC仓库:** [CVE-2025-32583](https://github.com/GadaLuBau1337/CVE-2025-32583)  

---

### [CVE-2021-4034](CVE-2021-4034-Milad-Rafie_PwnKit-Local-Privilege-Escalation-Vulnerability-Discovered-in-polkit-s-pkexec-CVE-2021-4034-.md) 🔴 ✅

**名称:** CVE-2021-4034-Polkit pkexec权限提升漏洞  
**类型:** 本地权限提升  
**风险:** 高危，允许低权限用户获得root权限  
**投毒风险:** 0%  
**发现时间:** 2025-05-16  
**POC仓库:** [PwnKit-Local-Privilege-Escalation-Vulnerability-Discovered-in-polkit-s-pkexec-CVE-2021-4034-](https://github.com/Milad-Rafie/PwnKit-Local-Privilege-Escalation-Vulnerability-Discovered-in-polkit-s-pkexec-CVE-2021-4034-)  

---

### [CVE-2021-4428](CVE-2021-4428-CERT-hr_Log4Shell.md)  

**名称:** CVE-2021-4428 - what3words Autosuggest Plugin 信息泄露  
**类型:** 信息泄露  
**风险:** 低危  
**投毒风险:** 0%  
**发现时间:** 2025-05-16  
**POC仓库:** [Log4Shell](https://github.com/CERT-hr/Log4Shell)  

---

### [CVE-2021-4428](CVE-2021-4428-GianlucaSanfi_cve-2021-4428.md)  

**名称:** CVE-2021-4428-what3words Autosuggest Plugin-信息泄露  
**类型:** 信息泄露  
**风险:** 低危，可能泄露敏感配置信息或其他非关键数据  
**投毒风险:** 0%  
**发现时间:** 2025-05-16  
**POC仓库:** [cve-2021-4428](https://github.com/GianlucaSanfi/cve-2021-4428)  

---

### [CVE-2025-47646](CVE-2025-47646-Nxploited_CVE-2025-47646.md) 🔴 ✅

**名称:** CVE-2025-47646 - PSW Front-end Login & Registration 权限绕过  
**类型:** 权限绕过  
**风险:** 高危，可能导致账户被恶意注册甚至管理员权限被获取  
**投毒风险:** 1%  
**发现时间:** 2025-05-16  
**POC仓库:** [CVE-2025-47646](https://github.com/Nxploited/CVE-2025-47646)  

---

### [CVE-2025-4428](CVE-2025-4428-xie-22_CVE-2025-4428.md) 🔴 ✅

**名称:** CVE-2025-4428 - Ivanti EPMM 远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，允许认证后的攻击者执行任意代码  
**投毒风险:** 5%  
**发现时间:** 2025-05-16  
**POC仓库:** [CVE-2025-4428](https://github.com/xie-22/CVE-2025-4428)  

---

### [CVE-2025-32407](CVE-2025-32407-diegovargasj_CVE-2025-32407.md) 🔴 ✅

**名称:** CVE-2025-32407-Samsung Internet for Galaxy Watch-TLS证书验证绕过  
**类型:** TLS证书验证绕过  
**风险:** 高危，可能导致中间人攻击，敏感信息泄露和流量篡改  
**投毒风险:** 1%  
**发现时间:** 2025-05-15  
**POC仓库:** [CVE-2025-32407](https://github.com/diegovargasj/CVE-2025-32407)  

---

### [CVE-2023-20198](CVE-2023-20198-DOMINIC471_qub-network-security-cve-2023-20198.md) 🔴 ✅

**名称:** CVE-2023-20198 - Cisco IOS XE Web UI 权限提升  
**类型:** 权限提升  
**风险:** 高危，允许未授权的远程攻击者创建具有特权级别15的账户，完全控制受影响的设备。  
**投毒风险:** 10%  
**发现时间:** 2025-05-15  
**POC仓库:** [qub-network-security-cve-2023-20198](https://github.com/DOMINIC471/qub-network-security-cve-2023-20198)  

---

### [CVE-2025-4688](CVE-2025-4688-sahici_CVE-2025-4688.md)  ✅

**名称:** CVE-2025-4688  
**类型:** 未知  
**风险:** 待评估  
**投毒风险:** 0%  
**发现时间:** 2025-05-15  
**POC仓库:** [CVE-2025-4688](https://github.com/sahici/CVE-2025-4688)  

---

### [CVE-2025-4686](CVE-2025-4686-sahici_CVE-2025-4686.md)  ✅

**名称:** CVE-2025-4686  
**类型:** 未知  
**风险:** 未评估  
**投毒风险:** 80%  
**发现时间:** 2025-05-15  
**POC仓库:** [CVE-2025-4686](https://github.com/sahici/CVE-2025-4686)  

---

### [CVE-2025-3605](CVE-2025-3605-GadaLuBau1337_CVE-2025-3605.md) 🔴 ✅

**名称:** CVE-2025-3605-Frontend Login and Registration Blocks-权限提升  
**类型:** 权限提升  
**风险:** 高危，可能导致账户接管和完全控制 WordPress 站点  
**投毒风险:** 5%  
**发现时间:** 2025-05-15  
**POC仓库:** [CVE-2025-3605](https://github.com/GadaLuBau1337/CVE-2025-3605)  

---

### [CVE-2024-51793](CVE-2024-51793-KTN1990_CVE-2024-51793.md) 🔴 ✅

**名称:** CVE-2024-51793-Computer Repair Shop-任意文件上传  
**类型:** 任意文件上传  
**风险:** 高危，允许上传Web Shell到Web服务器，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-05-15  
**POC仓库:** [CVE-2024-51793](https://github.com/KTN1990/CVE-2024-51793)  

---

### [CVE-2025-4190](CVE-2025-4190-GadaLuBau1337_CVE-2025-4190.md) 🔴 ✅

**名称:** CVE-2025-4190 - WordPress CSV Mass Importer Arbitrary File Upload  
**类型:** 任意文件上传  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-05-15  
**POC仓库:** [CVE-2025-4190](https://github.com/GadaLuBau1337/CVE-2025-4190)  

---

### [CVE-2025-4427](CVE-2025-4427-watchtowrlabs_watchTowr-vs-Ivanti-EPMM-CVE-2025-4427-CVE-2025-4428.md) 🟡 ✅

**名称:** CVE-2025-4427-Ivanti EPMM-身份验证绕过  
**类型:** 身份验证绕过  
**风险:** 中危，可能导致未经授权的访问和信息泄露  
**投毒风险:** 5%  
**发现时间:** 2025-05-15  
**POC仓库:** [watchTowr-vs-Ivanti-EPMM-CVE-2025-4427-CVE-2025-4428](https://github.com/watchtowrlabs/watchTowr-vs-Ivanti-EPMM-CVE-2025-4427-CVE-2025-4428)  

---

### [CVE-2025-4094](CVE-2025-4094-POCPioneer_CVE-2025-4094-POC.md) 🔴 ✅

**名称:** CVE-2025-4094-WordPress Digits OTP Bypass  
**类型:** 身份验证绕过  
**风险:** 高危，可能导致未经授权的帐户访问  
**投毒风险:** 1%  
**发现时间:** 2025-05-15  
**POC仓库:** [CVE-2025-4094-POC](https://github.com/POCPioneer/CVE-2025-4094-POC)  

---

### [CVE-2025-24813](CVE-2025-24813-maliqto_PoC-CVE-2025-24813.md) 🔴 ✅

**名称:** CVE-2025-24813 - Apache Tomcat 路径等价和反序列化漏洞  
**类型:** 路径等价/反序列化  
**风险:** 高危，可能导致远程代码执行和信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-05-15  
**POC仓库:** [PoC-CVE-2025-24813](https://github.com/maliqto/PoC-CVE-2025-24813)  

---

### [CVE-2025-30397](CVE-2025-30397-Sratet_CVE-2025-30397-RCE.md) 🔴 

**名称:** CVE-2025-30397-Microsoft Scripting Engine Type Confusion RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，允许攻击者在目标系统上执行任意代码  
**投毒风险:** 70%  
**发现时间:** 2025-05-15  
**POC仓库:** [CVE-2025-30397-RCE](https://github.com/Sratet/CVE-2025-30397-RCE)  

---

### [CVE-2020-14883](CVE-2020-14883-murataydemir_CVE-2020-14883.md) 🔴 ✅

**名称:** CVE-2020-14883 - Oracle WebLogic Server 远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-05-15  
**POC仓库:** [CVE-2020-14883](https://github.com/murataydemir/CVE-2020-14883)  

---

### [CVE-2020-14883](CVE-2020-14883-B1anda0_CVE-2020-14883.md) 🔴 ✅

**名称:** CVE-2020-14883 WebLogic 身份验证绕过  
**类型:** 身份验证绕过  
**风险:** 高危，可能导致服务器接管  
**投毒风险:** 1%  
**发现时间:** 2025-05-15  
**POC仓库:** [CVE-2020-14883](https://github.com/B1anda0/CVE-2020-14883)  

---

### [CVE-2020-14883](CVE-2020-14883-fan1029_CVE-2020-14883EXP.md) 🔴 ✅

**名称:** CVE-2020-14883-Oracle WebLogic Server-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，允许未授权用户接管WebLogic服务器  
**投毒风险:** 5%  
**发现时间:** 2025-05-15  
**POC仓库:** [CVE-2020-14883EXP](https://github.com/fan1029/CVE-2020-14883EXP)  

---

### [CVE-2020-14883](CVE-2020-14883-Osyanina_westone-CVE-2020-14883-scanner.md) 🔴 ✅

**名称:** CVE-2020-14883-Oracle WebLogic Server 远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-05-15  
**POC仓库:** [westone-CVE-2020-14883-scanner](https://github.com/Osyanina/westone-CVE-2020-14883-scanner)  

---

### [CVE-2020-14883](CVE-2020-14883-amacloudobia_CVE-2020-14883.md) 🔴 ✅

**名称:** CVE-2020-14883-WebLogic-RCE  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-05-15  
**POC仓库:** [CVE-2020-14883](https://github.com/amacloudobia/CVE-2020-14883)  

---

### [CVE-2021-3156](CVE-2021-3156-duongdz96_CVE-2021-3156-main.md) 🔴 ✅

**名称:** CVE-2021-3156 (Sudo Baron Samedit)  
**类型:** 堆缓冲区溢出  
**风险:** 高危，任何本地用户都可利用此漏洞提升权限至root  
**投毒风险:** 10%  
**发现时间:** 2025-05-15  
**POC仓库:** [CVE-2021-3156-main](https://github.com/duongdz96/CVE-2021-3156-main)  

---

### [CVE-2025-4094](CVE-2025-4094-starawneh_CVE-2025-4094.md) 🔴 ✅

**名称:** CVE-2025-4094 - WordPress Digits Plugin < 8.4.6.1 - OTP Authentication Bypass  
**类型:** OTP Authentication Bypass via Brute-force  
**风险:** 高危，可能导致账号接管和未授权访问  
**投毒风险:** 0%  
**发现时间:** 2025-05-15  
**POC仓库:** [CVE-2025-4094](https://github.com/starawneh/CVE-2025-4094)  

---

### [CVE-2025-31258](CVE-2025-31258-BODE987_CVE-2025-31258-PoC.md) 🔴 ✅

**名称:** CVE-2025-31258-macOS-沙箱逃逸  
**类型:** 沙箱逃逸  
**风险:** 高危，允许应用突破沙箱限制，可能导致系统资源访问和权限提升  
**投毒风险:** 10%  
**发现时间:** 2025-05-15  
**POC仓库:** [CVE-2025-31258-PoC](https://github.com/BODE987/CVE-2025-31258-PoC)  

---

### [CVE-2023-3079](CVE-2023-3079-mistymntncop_CVE-2023-3079.md) 🔴 ✅

**名称:** CVE-2023-3079 Chrome V8 类型混淆漏洞  
**类型:** 类型混淆  
**风险:** 高危，可能导致堆损坏和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-05-15  
**POC仓库:** [CVE-2023-3079](https://github.com/mistymntncop/CVE-2023-3079)  

---

### [CVE-2025-32756](CVE-2025-32756-m4s1um_CVE-2025-32756-RCE-PoC.md) 🔴 

**名称:** CVE-2025-32756-Fortinet多个产品-栈溢出RCE  
**类型:** 栈溢出  
**风险:** 高危，远程代码执行  
**投毒风险:** 60%  
**发现时间:** 2025-05-15  
**POC仓库:** [CVE-2025-32756-RCE-PoC](https://github.com/m4s1um/CVE-2025-32756-RCE-PoC)  

---

### [CVE-2020-17530](CVE-2020-17530-fatkz_CVE-2020-17530.md) 🔴 ✅

**名称:** CVE-2020-17530-Apache Struts2-OGNL注入  
**类型:** OGNL注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-05-14  
**POC仓库:** [CVE-2020-17530](https://github.com/fatkz/CVE-2020-17530)  

---

### [CVE-2024-37010](CVE-2024-37010-SarpantKeltiek_CVE-2024-37010.md) 🟡 ✅

**名称:** CVE-2024-37010 Owncloud 外部存储不安全直接对象引用  
**类型:** 不安全直接对象引用 (IDOR)  
**风险:** 中危，可能导致未授权访问其他用户的外部存储  
**投毒风险:** 10%  
**发现时间:** 2025-05-14  
**POC仓库:** [CVE-2024-37010](https://github.com/SarpantKeltiek/CVE-2024-37010)  

---

### [CVE-2025-24132](CVE-2025-24132-Feralthedogg_CVE-2025-24132-Scanner.md) 🟡 ✅

**名称:** CVE-2025-24132 - AirPlay 远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 中危，可能导致应用意外终止  
**投毒风险:** 10%  
**发现时间:** 2025-05-14  
**POC仓库:** [CVE-2025-24132-Scanner](https://github.com/Feralthedogg/CVE-2025-24132-Scanner)  

---

### [CVE-2021-42694](CVE-2021-42694-simplylu_CVE-2021-42694.md) 🔴 ✅

**名称:** CVE-2021-42694-Unicode Homoglyph Injection  
**类型:** 代码注入  
**风险:** 高危，可能导致代码执行，权限提升  
**投毒风险:** 10%  
**发现时间:** 2025-05-14  
**POC仓库:** [CVE-2021-42694](https://github.com/simplylu/CVE-2021-42694)  

---

### [CVE-2021-42694](CVE-2021-42694-k271266_CVE-2021-42694.md) 🔴 ✅

**名称:** CVE-2021-42694-Unicode 欺骗  
**类型:** Unicode 欺骗/Trojan Source  
**风险:** 高危，可能导致代码注入和供应链攻击  
**投毒风险:** 0%  
**发现时间:** 2025-05-14  
**POC仓库:** [CVE-2021-42694](https://github.com/k271266/CVE-2021-42694)  

---

### [CVE-2018-25031](CVE-2018-25031-faccimatteo_CVE-2018-25031.md) 🟡 ✅

**名称:** CVE-2018-25031-Swagger UI-欺骗攻击/SSRF  
**类型:** 欺骗攻击/SSRF  
**风险:** 中危，可能导致信息泄露或SSRF  
**投毒风险:** 0%  
**发现时间:** 2025-05-14  
**POC仓库:** [CVE-2018-25031](https://github.com/faccimatteo/CVE-2018-25031)  

---

### [CVE-2025-44184](CVE-2025-44184-cumakurt_CVE-2025-44184-SourceCodester-Best-Employee-Management-System-1.0.md) 🔴 ✅

**名称:** CVE-2025-44184 - SourceCodester Best Employee Management System v1.0 - Stored XSS  
**类型:** Stored Cross-Site Scripting (XSS)  
**风险:** 高危，可能导致信息泄露，会话劫持，恶意代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-05-14  
**POC仓库:** [CVE-2025-44184-SourceCodester-Best-Employee-Management-System-1.0](https://github.com/cumakurt/CVE-2025-44184-SourceCodester-Best-Employee-Management-System-1.0)  

---

### [CVE-2025-27636](CVE-2025-27636-akamai_CVE-2025-27636-Apache-Camel-PoC.md) 🟡 ✅

**名称:** CVE-2025-27636-Apache Camel-Header注入  
**类型:** Header注入/方法调用  
**风险:** 中危，可能导致远程代码执行或未经授权的访问  
**投毒风险:** 5%  
**发现时间:** 2025-05-14  
**POC仓库:** [CVE-2025-27636-Apache-Camel-PoC](https://github.com/akamai/CVE-2025-27636-Apache-Camel-PoC)  

---

### [CVE-2025-27636](CVE-2025-27636-enochgitgamefied_CVE-2025-27636-Pratctical-Lab.md) 🔴 ✅

**名称:** CVE-2025-27636-Apache Camel-Header注入  
**类型:** Header注入/RCE  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-05-14  
**POC仓库:** [CVE-2025-27636-Pratctical-Lab](https://github.com/enochgitgamefied/CVE-2025-27636-Pratctical-Lab)  

---

### [CVE-2015-3306](CVE-2015-3306-t0kx_exploit-CVE-2015-3306.md) 🔴 ✅

**名称:** CVE-2015-3306 ProFTPD mod_copy 任意文件读写  
**类型:** 任意文件读写  
**风险:** 高危，可能导致敏感信息泄露，甚至远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-05-14  
**POC仓库:** [exploit-CVE-2015-3306](https://github.com/t0kx/exploit-CVE-2015-3306)  

---

### [CVE-2015-3306](CVE-2015-3306-shk0x_cpx_proftpd.md) 🔴 ✅

**名称:** CVE-2015-3306 - ProFTPD mod_copy 文件访问控制漏洞  
**类型:** 文件读取/写入  
**风险:** 高危，可读取任意文件，写入任意文件，甚至可导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-05-14  
**POC仓库:** [cpx_proftpd](https://github.com/shk0x/cpx_proftpd)  

---

### [CVE-2015-3306](CVE-2015-3306-nootropics_propane.md) 🔴 ✅

**名称:** CVE-2015-3306-ProFTPD-任意文件读写  
**类型:** 任意文件读写  
**风险:** 高危，可能导致敏感信息泄露和远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-05-14  
**POC仓库:** [propane](https://github.com/nootropics/propane)  

---

### [CVE-2015-3306](CVE-2015-3306-davidtavarez_CVE-2015-3306.md) 🔴 ✅

**名称:** CVE-2015-3306 ProFTPD mod_copy 远程命令执行  
**类型:** 远程命令执行  
**风险:** 高危，可能导致任意文件读取、写入以及远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-05-14  
**POC仓库:** [CVE-2015-3306](https://github.com/davidtavarez/CVE-2015-3306)  

---

### [CVE-2015-3306](CVE-2015-3306-cdedmondson_Modified-CVE-2015-3306-Exploit.md) 🔴 ✅

**名称:** CVE-2015-3306 ProFTPD mod_copy 任意文件读写漏洞  
**类型:** 任意文件读写  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-05-14  
**POC仓库:** [Modified-CVE-2015-3306-Exploit](https://github.com/cdedmondson/Modified-CVE-2015-3306-Exploit)  

---

### [CVE-2015-3306](CVE-2015-3306-cd6629_CVE-2015-3306-Python-PoC.md) 🔴 ✅

**名称:** CVE-2015-3306-ProFTPD mod_copy 远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可远程读取和写入任意文件，最终执行任意代码  
**投毒风险:** 5%  
**发现时间:** 2025-05-14  
**POC仓库:** [CVE-2015-3306-Python-PoC](https://github.com/cd6629/CVE-2015-3306-Python-PoC)  

---

### [CVE-2015-3306](CVE-2015-3306-cved-sources_cve-2015-3306.md) 🔴 ✅

**名称:** CVE-2015-3306-ProFTPD-任意文件读写  
**类型:** 任意文件读写  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-05-14  
**POC仓库:** [cve-2015-3306](https://github.com/cved-sources/cve-2015-3306)  

---

### [CVE-2015-3306](CVE-2015-3306-0xm4ud_ProFTPD_CVE-2015-3306.md) 🔴 ✅

**名称:** CVE-2015-3306-ProFTPD-mod_copy文件读写  
**类型:** 文件读写  
**风险:** 高危，可能导致信息泄露和远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-05-14  
**POC仓库:** [ProFTPD_CVE-2015-3306](https://github.com/0xm4ud/ProFTPD_CVE-2015-3306)  

---

### [CVE-2015-3306](CVE-2015-3306-jptr218_proftpd_bypass.md) 🔴 ✅

**名称:** CVE-2015-3306-ProFTPD-mod_copy任意文件读写  
**类型:** 任意文件读写  
**风险:** 高危，可能导致信息泄露和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-05-14  
**POC仓库:** [proftpd_bypass](https://github.com/jptr218/proftpd_bypass)  

---

### [CVE-2015-3306](CVE-2015-3306-hackarada_cve-2015-3306.md) 🔴 ✅

**名称:** CVE-2015-3306 - ProFTPD mod_copy 任意文件读写  
**类型:** 任意文件读写  
**风险:** 高危，可能导致敏感信息泄露和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-05-14  
**POC仓库:** [cve-2015-3306](https://github.com/hackarada/cve-2015-3306)  

---

### [CVE-2015-3306](CVE-2015-3306-JoseLRC97_ProFTPd-1.3.5-mod_copy-Remote-Command-Execution.md) 🔴 ✅

**名称:** CVE-2015-3306 ProFTPD mod_copy 文件读写漏洞  
**类型:** 文件读写  
**风险:** 高危，可能导致敏感信息泄露和远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-05-14  
**POC仓库:** [ProFTPd-1.3.5-mod_copy-Remote-Command-Execution](https://github.com/JoseLRC97/ProFTPd-1.3.5-mod_copy-Remote-Command-Execution)  

---

### [CVE-2015-3306](CVE-2015-3306-Z3R0-0x30_CVE-2015-3306.md) 🔴 ✅

**名称:** CVE-2015-3306-ProFTPD-mod_copy任意文件读写  
**类型:** 任意文件读写  
**风险:** 高危，可能导致信息泄露和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-05-14  
**POC仓库:** [CVE-2015-3306](https://github.com/Z3R0-0x30/CVE-2015-3306)  

---

### [CVE-2021-4034](CVE-2021-4034-Z3R0-0x30_CVE-2021-4034.md) 🔴 ✅

**名称:** CVE-2021-4034-Polkit-pkexec本地提权  
**类型:** 本地权限提升  
**风险:** 高危，可使普通用户获得root权限  
**投毒风险:** 5%  
**发现时间:** 2025-05-14  
**POC仓库:** [CVE-2021-4034](https://github.com/Z3R0-0x30/CVE-2021-4034)  

---

### [CVE-2025-29824](CVE-2025-29824-encrypter15_CVE-2025-29824.md) 🔴 ✅

**名称:** CVE-2025-29824 Windows CLFS 驱动程序特权提升漏洞  
**类型:** 特权提升  
**风险:** 高危，本地权限提升至SYSTEM  
**投毒风险:** 10%  
**发现时间:** 2025-05-14  
**POC仓库:** [CVE-2025-29824](https://github.com/encrypter15/CVE-2025-29824)  

---

### [CVE-2025-2294](CVE-2025-2294-Yucaerin_CVE-2025-2294.md) 🔴 ✅

**名称:** CVE-2025-2294-Kubio AI Page Builder-本地文件包含  
**类型:** 本地文件包含 (LFI)  
**风险:** 高危，可能导致敏感信息泄露和远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-05-13  
**POC仓库:** [CVE-2025-2294](https://github.com/Yucaerin/CVE-2025-2294)  

---

### [CVE-2025-3248](CVE-2025-3248-vigilante-1337_CVE-2025-3248.md) 🔴 ✅

**名称:** CVE-2025-3248-Langflow-代码注入  
**类型:** 代码注入  
**风险:** 高危，远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-05-13  
**POC仓库:** [CVE-2025-3248](https://github.com/vigilante-1337/CVE-2025-3248)  

---

### [CVE-2021-3560](CVE-2021-3560-MandipJoshi_CVE-2021-3560.md) 🔴 ✅

**名称:** CVE-2021-3560 - Polkit 本地提权漏洞  
**类型:** 本地提权  
**风险:** 高危，可能导致任意用户提升至root权限  
**投毒风险:** 10%  
**发现时间:** 2025-05-13  
**POC仓库:** [CVE-2021-3560](https://github.com/MandipJoshi/CVE-2021-3560)  

---

### [CVE-2025-46721](CVE-2025-46721-justinas_nosurf-cve-2025-46721.md) 🟡 ✅

**名称:** CVE-2025-46721-justinas/nosurf-CSRF  
**类型:** CSRF  
**风险:** 中危，允许跨域请求，可能导致未经授权的状态更改  
**投毒风险:** 10%  
**发现时间:** 2025-05-13  
**POC仓库:** [nosurf-cve-2025-46721](https://github.com/justinas/nosurf-cve-2025-46721)  

---

### [CVE-2018-14498](CVE-2018-14498-h31md4llr_libjpeg_cve-2018-14498_2.md) 🟡 ✅

**名称:** CVE-2018-14498-libjpeg-turbo/MozJPEG-堆缓冲区过读  
**类型:** 堆缓冲区过读  
**风险:** 中危，可能导致拒绝服务（应用程序崩溃）  
**投毒风险:** 10%  
**发现时间:** 2025-05-13  
**POC仓库:** [libjpeg_cve-2018-14498_2](https://github.com/h31md4llr/libjpeg_cve-2018-14498_2)  

---

### [CVE-2018-14498](CVE-2018-14498-h31md4llr_libjpeg_cve-2018-14498.md) 🟡 ✅

**名称:** CVE-2018-14498-libjpeg-turbo/MozJPEG-堆缓冲区过度读取  
**类型:** 堆缓冲区过度读取  
**风险:** 中危，可能导致拒绝服务（应用程序崩溃）  
**投毒风险:** 1%  
**发现时间:** 2025-05-13  
**POC仓库:** [libjpeg_cve-2018-14498](https://github.com/h31md4llr/libjpeg_cve-2018-14498)  

---

### [CVE-2022-21661](CVE-2022-21661-purple-WL_wordpress-CVE-2022-21661.md) 🔴 ✅

**名称:** CVE-2022-21661-WordPress-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露和远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-05-13  
**POC仓库:** [wordpress-CVE-2022-21661](https://github.com/purple-WL/wordpress-CVE-2022-21661)  

---

### [CVE-2022-21661](CVE-2022-21661-0x4E0x650x6F_Wordpress-cve-CVE-2022-21661.md) 🔴 ✅

**名称:** CVE-2022-21661-WordPress-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-05-13  
**POC仓库:** [Wordpress-cve-CVE-2022-21661](https://github.com/0x4E0x650x6F/Wordpress-cve-CVE-2022-21661)  

---

### [CVE-2022-21661](CVE-2022-21661-guestzz_CVE-2022-21661.md) 🔴 ✅

**名称:** CVE-2022-21661-WordPress-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露、数据篡改和远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-05-13  
**POC仓库:** [CVE-2022-21661](https://github.com/guestzz/CVE-2022-21661)  

---

### [CVE-2022-21661](CVE-2022-21661-safe3s_CVE-2022-21661.md) 🔴 ✅

**名称:** CVE-2022-21661-WordPress-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露和远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-05-13  
**POC仓库:** [CVE-2022-21661](https://github.com/safe3s/CVE-2022-21661)  

---

### [CVE-2022-21661](CVE-2022-21661-z92g_CVE-2022-21661.md) 🔴 ✅

**名称:** CVE-2022-21661-WordPress-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露、数据篡改和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-05-13  
**POC仓库:** [CVE-2022-21661](https://github.com/z92g/CVE-2022-21661)  

---

### [CVE-2022-21661](CVE-2022-21661-sealldeveloper_CVE-2022-21661-PoC.md) 🔴 ✅

**名称:** CVE-2022-21661-WordPress-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露、数据篡改甚至远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-05-13  
**POC仓库:** [CVE-2022-21661-PoC](https://github.com/sealldeveloper/CVE-2022-21661-PoC)  

---

### [CVE-2022-21661](CVE-2022-21661-daniel616_CVE-2022-21661-Demo.md) 🔴 ✅

**名称:** CVE-2022-21661-WordPress-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露、数据篡改和远程代码执行  
**投毒风险:** 20%  
**发现时间:** 2025-05-13  
**POC仓库:** [CVE-2022-21661-Demo](https://github.com/daniel616/CVE-2022-21661-Demo)  

---

### [CVE-2022-21661](CVE-2022-21661-TAPESH-TEAM_CVE-2022-21661-WordPress-Core-5.8.2-WP_Query-SQL-Injection.md) 🔴 ✅

**名称:** CVE-2022-21661-WordPress-WP_Query-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致敏感信息泄露、数据篡改、甚至服务器控制  
**投毒风险:** 10%  
**发现时间:** 2025-05-13  
**POC仓库:** [CVE-2022-21661-WordPress-Core-5.8.2-WP_Query-SQL-Injection](https://github.com/TAPESH-TEAM/CVE-2022-21661-WordPress-Core-5.8.2-WP_Query-SQL-Injection)  

---

### [CVE-2022-21661](CVE-2022-21661-WellingtonEspindula_SSI-CVE-2022-21661.md) 🔴 ✅

**名称:** CVE-2022-21661 - WordPress SQL 注入  
**类型:** SQL 注入  
**风险:** 高危，可能导致数据泄露、数据篡改和权限提升  
**投毒风险:** 0%  
**发现时间:** 2025-05-13  
**POC仓库:** [SSI-CVE-2022-21661](https://github.com/WellingtonEspindula/SSI-CVE-2022-21661)  

---

### [CVE-2022-21661](CVE-2022-21661-p4ncontomat3_CVE-2022-21661.md) 🔴 ✅

**名称:** CVE-2022-21661-WordPress-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据库信息泄露和任意代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-05-13  
**POC仓库:** [CVE-2022-21661](https://github.com/p4ncontomat3/CVE-2022-21661)  

---

### [CVE-2022-21661](CVE-2022-21661-CharonDefalt_WordPress--CVE-2022-21661.md) 🔴 ✅

**名称:** CVE-2022-21661-WordPress-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露和远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-05-13  
**POC仓库:** [WordPress--CVE-2022-21661](https://github.com/CharonDefalt/WordPress--CVE-2022-21661)  

---

### [CVE-2022-21661](CVE-2022-21661-w0r1i0g1ht_CVE-2022-21661.md) 🔴 ✅

**名称:** CVE-2022-21661-WordPress-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露和远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-05-13  
**POC仓库:** [CVE-2022-21661](https://github.com/w0r1i0g1ht/CVE-2022-21661)  

---

### [CVE-2022-21661](CVE-2022-21661-kittypurrnaz_cve-2022-21661.md) 🔴 ✅

**名称:** CVE-2022-21661-WordPress-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露和远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-05-13  
**POC仓库:** [cve-2022-21661](https://github.com/kittypurrnaz/cve-2022-21661)  

---

### [CVE-2022-21661](CVE-2022-21661-Fauzan-Aldi_CVE-2022-21661.md) 🔴 ✅

**名称:** CVE-2022-21661-WordPress-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-05-13  
**POC仓库:** [CVE-2022-21661](https://github.com/Fauzan-Aldi/CVE-2022-21661)  

---

### [CVE-2024-55511](CVE-2024-55511-nikosecurity_CVE-2024-55511.md) 🔴 ✅

**名称:** CVE-2024-55511-Macrium Reflect-空指针解引用  
**类型:** 空指针解引用  
**风险:** 高危，可能导致系统崩溃或权限提升  
**投毒风险:** 10%  
**发现时间:** 2025-05-13  
**POC仓库:** [CVE-2024-55511](https://github.com/nikosecurity/CVE-2024-55511)  

---

### [CVE-2025-31258](CVE-2025-31258-wh1te4ever_CVE-2025-31258-PoC.md) 🔴 ✅

**名称:** CVE-2025-31258-macOS-沙箱逃逸  
**类型:** 沙箱逃逸  
**风险:** 高危，允许应用程序突破沙箱限制，执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-05-13  
**POC仓库:** [CVE-2025-31258-PoC](https://github.com/wh1te4ever/CVE-2025-31258-PoC)  

---

### [CVE-2024-55466](CVE-2024-55466-cybsecsid_ThingsBoard-CVE-2024-55466.md) 🔴 ✅

**名称:** ThingsBoard Stored XSS 导致权限提升  
**类型:** 存储型跨站脚本 (Stored XSS)  
**风险:** 高危，通过盗取身份验证令牌可导致权限提升  
**投毒风险:** 0%  
**发现时间:** 2025-05-12  
**POC仓库:** [ThingsBoard-CVE-2024-55466](https://github.com/cybsecsid/ThingsBoard-CVE-2024-55466)  

---

### [CVE-2024-55466](CVE-2024-55466-cybsecsid_ThingsBoard-IoT-Platform-CVE-2024-55466.md) 🔴 ✅

**名称:** ThingsBoard Stored XSS Privilege Escalation  
**类型:** Stored Cross-Site Scripting (XSS)  
**风险:** CRITICAL (CVSS 8.8), 通过盗取认证令牌提升权限  
**投毒风险:** 10%  
**发现时间:** 2025-05-12  
**POC仓库:** [ThingsBoard-IoT-Platform-CVE-2024-55466](https://github.com/cybsecsid/ThingsBoard-IoT-Platform-CVE-2024-55466)  

---

### [CVE-2025-24203](CVE-2025-24203-GeoSn0w_CVE-2025-24203-iOS-Exploit-in-Swift.md) 🟡 ✅

**名称:** CVE-2025-24203-iOS文件系统修改漏洞  
**类型:** 文件系统修改  
**风险:** 中危，可能导致文件系统受损  
**投毒风险:** 10%  
**发现时间:** 2025-05-12  
**POC仓库:** [CVE-2025-24203-iOS-Exploit-in-Swift](https://github.com/GeoSn0w/CVE-2025-24203-iOS-Exploit-in-Swift)  

---

### [CVE-2023-34732](CVE-2023-34732-saykino_CVE-2023-34732.md) 🔴 ✅

**名称:** CVE-2023-34732 - Flytxt NEON-dX 权限绕过漏洞  
**类型:** 不正确的权限控制/暴力破解  
**风险:** 高危，可能导致任意用户密码重置  
**投毒风险:** 10%  
**发现时间:** 2025-05-12  
**POC仓库:** [CVE-2023-34732](https://github.com/saykino/CVE-2023-34732)  

---

### [CVE-2024-10220](CVE-2024-10220-mochizuki875_CVE-2024-10220-githooks.md) 🔴 ✅

**名称:** CVE-2024-10220-Kubelet-命令执行  
**类型:** 命令执行  
**风险:** 高危，可能导致节点接管  
**投毒风险:** 10%  
**发现时间:** 2025-05-12  
**POC仓库:** [CVE-2024-10220-githooks](https://github.com/mochizuki875/CVE-2024-10220-githooks)  

---

### [CVE-2024-10220](CVE-2024-10220-any2sec_cve-2024-10220.md) 🔴 ✅

**名称:** CVE-2024-10220-Kubernetes-Kubelet任意命令执行  
**类型:** 任意命令执行  
**风险:** 高危，可能导致节点被完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-05-12  
**POC仓库:** [cve-2024-10220](https://github.com/any2sec/cve-2024-10220)  

---

### [CVE-2024-10220](CVE-2024-10220-XiaomingX_cve-2024-10220-githooks.md) 🔴 ✅

**名称:** CVE-2024-10220-Kubernetes-Kubelet-gitRepo任意命令执行  
**类型:** 任意命令执行  
**风险:** 高危，可能导致节点接管  
**投毒风险:** 10%  
**发现时间:** 2025-05-12  
**POC仓库:** [cve-2024-10220-githooks](https://github.com/XiaomingX/cve-2024-10220-githooks)  

---

### [CVE-2024-10220](CVE-2024-10220-filipzag_CVE-2024-10220.md) 🔴 ✅

**名称:** CVE-2024-10220-Kubernetes-kubelet-gitRepo-命令执行  
**类型:** 命令执行  
**风险:** 高危，允许攻击者在主机节点上执行任意命令，可能导致集群完全受控。  
**投毒风险:** 0%  
**发现时间:** 2025-05-12  
**POC仓库:** [CVE-2024-10220](https://github.com/filipzag/CVE-2024-10220)  

---

### [CVE-2024-10220](CVE-2024-10220-candranapits_poc-CVE-2024-10220.md) 🔴 ✅

**名称:** CVE-2024-10220  
**类型:** 任意命令执行  
**风险:** 高危，允许攻击者执行任意命令  
**投毒风险:** 0%  
**发现时间:** 2025-05-12  
**POC仓库:** [poc-CVE-2024-10220](https://github.com/candranapits/poc-CVE-2024-10220)  

---

### [CVE-2024-10220](CVE-2024-10220-orgC_CVE-2024-10220-demo.md) 🔴 ✅

**名称:** CVE-2024-10220-Kubelet-任意命令执行  
**类型:** 任意命令执行  
**风险:** 高危，可能导致节点被完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-05-12  
**POC仓库:** [CVE-2024-10220-demo](https://github.com/orgC/CVE-2024-10220-demo)  

---

### [CVE-2018-14498](CVE-2018-14498-h31md4llr_libjpeg_cve-2018-14498.md) 🔴 ✅

**名称:** CVE-2018-14498-libjpeg-turbo/MozJPEG-堆溢出  
**类型:** 堆缓冲区过读  
**风险:** 高危，可导致拒绝服务（应用程序崩溃）  
**投毒风险:** 10%  
**发现时间:** 2025-05-12  
**POC仓库:** [libjpeg_cve-2018-14498](https://github.com/h31md4llr/libjpeg_cve-2018-14498)  

---

### [CVE-2017-7117](CVE-2017-7117-rebelle3_cve-2017-7117.md) 🔴 ✅

**名称:** CVE-2017-7117-WebKit-类型混淆和UAF  
**类型:** 类型混淆和UAF(Use-After-Free)  
**风险:** 高危，可能导致任意代码执行或拒绝服务  
**投毒风险:** 10%  
**发现时间:** 2025-05-12  
**POC仓库:** [cve-2017-7117](https://github.com/rebelle3/cve-2017-7117)  

---

### [CVE-2017-7117](CVE-2017-7117-rebelle3_cve-2017-7117.md) 🔴 ✅

**名称:** CVE-2017-7117 - WebKit 内存损坏  
**类型:** 内存损坏  
**风险:** 高危，远程代码执行或拒绝服务  
**投毒风险:** 10%  
**发现时间:** 2025-05-12  
**POC仓库:** [cve-2017-7117](https://github.com/rebelle3/cve-2017-7117)  

---

### [CVE-2023-41992](CVE-2023-41992-karzanWang_CVE-2023-41992.md) 🔴 ✅

**名称:** CVE-2023-41992 - iOS/macOS 本地权限提升  
**类型:** 本地权限提升 (LPE)  
**风险:** 高危，允许本地攻击者提升权限  
**投毒风险:** 10%  
**发现时间:** 2025-05-12  
**POC仓库:** [CVE-2023-41992](https://github.com/karzanWang/CVE-2023-41992)  

---

### [CVE-2021-3156](CVE-2021-3156-mutur4_CVE-2021-3156.md) 🔴 ✅

**名称:** CVE-2021-3156 - Sudo Heap-Based Buffer Overflow  
**类型:** Heap-Based Buffer Overflow  
**风险:** 高危，可导致本地提权至 root  
**投毒风险:** 0%  
**发现时间:** 2025-05-12  
**POC仓库:** [CVE-2021-3156](https://github.com/mutur4/CVE-2021-3156)  

---

### [CVE-2021-3156](CVE-2021-3156-Sebastianbedoya25_CVE-2021-3156.md) 🔴 ✅

**名称:** CVE-2021-3156 - Sudo Heap-Based Buffer Overflow (Baron Samedit)  
**类型:** Heap-Based Buffer Overflow  
**风险:** 高危，允许本地普通用户提升权限至root  
**投毒风险:** 0%  
**发现时间:** 2025-05-12  
**POC仓库:** [CVE-2021-3156](https://github.com/Sebastianbedoya25/CVE-2021-3156)  

---

### [CVE-2021-3156](CVE-2021-3156-ten-ops_baron-samedit.md) 🔴 ✅

**名称:** CVE-2021-3156 (Baron Samedit)  
**类型:** 堆缓冲区溢出  
**风险:** 高危，本地提权至root  
**投毒风险:** 0%  
**发现时间:** 2025-05-12  
**POC仓库:** [baron-samedit](https://github.com/ten-ops/baron-samedit)  

---

### [CVE-2021-3156](CVE-2021-3156-shishirpandey18_CVE-2021-3156.md) 🔴 ✅

**名称:** CVE-2021-3156 - Sudo Baron Samedit 堆缓冲区溢出  
**类型:** 堆缓冲区溢出  
**风险:** 高危，可导致本地提权至root  
**投毒风险:** 1%  
**发现时间:** 2025-05-12  
**POC仓库:** [CVE-2021-3156](https://github.com/shishirpandey18/CVE-2021-3156)  

---

### [CVE-2021-3156](CVE-2021-3156-ypl6_heaplens.md) 🔴 ✅

**名称:** CVE-2021-3156 - Sudo Heap-Based Buffer Overflow (Baron Samedit)  
**类型:** 堆缓冲区溢出  
**风险:** 高危，可导致权限提升至 root  
**投毒风险:** 10%  
**发现时间:** 2025-05-12  
**POC仓库:** [heaplens](https://github.com/ypl6/heaplens)  

---

### [CVE-2021-3156](CVE-2021-3156-chenaotian_CVE-2021-3156.md) 🔴 ✅

**名称:** CVE-2021-3156 - Sudo Heap-Based Buffer Overflow  
**类型:** Heap-Based Buffer Overflow  
**风险:** 高危，本地提权至 root  
**投毒风险:** 0%  
**发现时间:** 2025-05-12  
**POC仓库:** [CVE-2021-3156](https://github.com/chenaotian/CVE-2021-3156)  

---

### [CVE-2024-43788](CVE-2024-43788-batzionb_webpack-cve-2024-43788.md) 🟡 ✅

**名称:** CVE-2024-43788-Webpack-XSS  
**类型:** XSS (DOM Clobbering)  
**风险:** 中危，可能导致用户凭据泄露或恶意脚本执行  
**投毒风险:** 10%  
**发现时间:** 2025-05-12  
**POC仓库:** [webpack-cve-2024-43788](https://github.com/batzionb/webpack-cve-2024-43788)  

---

### [CVE-2021-3156](CVE-2021-3156-CptGibbon_CVE-2021-3156.md) 🔴 ✅

**名称:** CVE-2021-3156-Sudo-Heap-Based缓冲区溢出  
**类型:** Heap-Based缓冲区溢出  
**风险:** 高危，允许本地用户提升权限至root  
**投毒风险:** 5%  
**发现时间:** 2025-05-12  
**POC仓库:** [CVE-2021-3156](https://github.com/CptGibbon/CVE-2021-3156)  

---

### [CVE-2021-3156](CVE-2021-3156-puckiestyle_CVE-2021-3156.md) 🔴 ✅

**名称:** CVE-2021-3156 (Sudo Baron Samedit)  
**类型:** 堆缓冲区溢出  
**风险:** 高危，允许本地普通用户提升权限至root  
**投毒风险:** 10%  
**发现时间:** 2025-05-12  
**POC仓库:** [CVE-2021-3156](https://github.com/puckiestyle/CVE-2021-3156)  

---

### [CVE-2021-3156](CVE-2021-3156-ret2basic_SudoScience.md) 🔴 ✅

**名称:** CVE-2021-3156 (Baron Samedit)  
**类型:** 堆缓冲区溢出  
**风险:** 高危，可导致本地提权至root  
**投毒风险:** 0%  
**发现时间:** 2025-05-12  
**POC仓库:** [SudoScience](https://github.com/ret2basic/SudoScience)  

---

### [CVE-2021-3156](CVE-2021-3156-stong_CVE-2021-3156.md) 🔴 ✅

**名称:** CVE-2021-3156 - Sudo Heap-Based Buffer Overflow  
**类型:** Heap-Based Buffer Overflow  
**风险:** 高危，允许本地用户提升权限至 root  
**投毒风险:** 5%  
**发现时间:** 2025-05-12  
**POC仓库:** [CVE-2021-3156](https://github.com/stong/CVE-2021-3156)  

---

### [CVE-2021-3156](CVE-2021-3156-q77190858_CVE-2021-3156.md) 🔴 ✅

**名称:** CVE-2021-3156 - Sudo Heap-Based Buffer Overflow (Baron Samedit)  
**类型:** Heap-Based Buffer Overflow  
**风险:** 高危，允许本地普通用户提升权限至root  
**投毒风险:** 0%  
**发现时间:** 2025-05-12  
**POC仓库:** [CVE-2021-3156](https://github.com/q77190858/CVE-2021-3156)  

---

### [CVE-2021-3156](CVE-2021-3156-arvindshima_CVE-2021-3156.md) 🔴 ✅

**名称:** CVE-2021-3156 - Sudo Baron Samedit  
**类型:** Heap-based Buffer Overflow  
**风险:** 高危，允许本地用户提升权限至root  
**投毒风险:** 5%  
**发现时间:** 2025-05-12  
**POC仓库:** [CVE-2021-3156](https://github.com/arvindshima/CVE-2021-3156)  

---

### [CVE-2021-3156](CVE-2021-3156-Mhackiori_CVE-2021-3156.md) 🔴 ✅

**名称:** CVE-2021-3156 (Baron Samedit)  
**类型:** 堆缓冲区溢出  
**风险:** 高危，本地权限提升至root  
**投毒风险:** 10%  
**发现时间:** 2025-05-12  
**POC仓库:** [CVE-2021-3156](https://github.com/Mhackiori/CVE-2021-3156)  

---

### [CVE-2021-3156](CVE-2021-3156-RodricBr_CVE-2021-3156.md) 🔴 ✅

**名称:** CVE-2021-3156-Sudo-Heap溢出  
**类型:** Heap-based 缓冲区溢出  
**风险:** 高危，允许本地用户提升权限至root  
**投毒风险:** 10%  
**发现时间:** 2025-05-12  
**POC仓库:** [CVE-2021-3156](https://github.com/RodricBr/CVE-2021-3156)  

---

### [CVE-2021-3156](CVE-2021-3156-PhuketIsland_CVE-2021-3156-centos7.md) 🔴 ✅

**名称:** CVE-2021-3156-Sudo-堆缓冲区溢出  
**类型:** 堆缓冲区溢出  
**风险:** 高危，允许本地普通用户提升权限至root  
**投毒风险:** 1%  
**发现时间:** 2025-05-12  
**POC仓库:** [CVE-2021-3156-centos7](https://github.com/PhuketIsland/CVE-2021-3156-centos7)  

---

### [CVE-2021-3156](CVE-2021-3156-0x4ndy_clif.md) 🔴 ✅

**名称:** CVE-2021-3156-Sudo-Heap-Based Buffer Overflow  
**类型:** Heap-Based Buffer Overflow  
**风险:** 高危，可导致权限提升至root  
**投毒风险:** 0%  
**发现时间:** 2025-05-12  
**POC仓库:** [clif](https://github.com/0x4ndy/clif)  

---

### [CVE-2021-3156](CVE-2021-3156-PurpleOzone_PE_CVE-CVE-2021-3156.md) 🔴 ✅

**名称:** CVE-2021-3156-Sudo-Heap-Based 缓冲区溢出  
**类型:** Heap-Based 缓冲区溢出  
**风险:** 高危，允许本地用户提升权限至 root  
**投毒风险:** 10%  
**发现时间:** 2025-05-12  
**POC仓库:** [PE_CVE-CVE-2021-3156](https://github.com/PurpleOzone/PE_CVE-CVE-2021-3156)  

---

### [CVE-2021-3156](CVE-2021-3156-asepsaepdin_CVE-2021-3156.md) 🔴 ✅

**名称:** CVE-2021-3156 - Sudo Heap-Based Buffer Overflow  
**类型:** Heap-Based Buffer Overflow  
**风险:** 高危，允许本地用户提升权限至root  
**投毒风险:** 10%  
**发现时间:** 2025-05-12  
**POC仓库:** [CVE-2021-3156](https://github.com/asepsaepdin/CVE-2021-3156)  

---

### [CVE-2021-3156](CVE-2021-3156-hycheng15_CVE-2021-3156.md) 🔴 ✅

**名称:** CVE-2021-3156 Sudo Baron Samedit 权限提升漏洞  
**类型:** 堆溢出  
**风险:** 高危，本地权限提升至root  
**投毒风险:** 10%  
**发现时间:** 2025-05-12  
**POC仓库:** [CVE-2021-3156](https://github.com/hycheng15/CVE-2021-3156)  

---

### [CVE-2021-3156](CVE-2021-3156-DDayLuong_CVE-2021-3156.md) 🔴 ✅

**名称:** CVE-2021-3156-Sudo-Heap缓冲区溢出  
**类型:** Heap缓冲区溢出  
**风险:** 高危，可提升至root权限  
**投毒风险:** 10%  
**发现时间:** 2025-05-12  
**POC仓库:** [CVE-2021-3156](https://github.com/DDayLuong/CVE-2021-3156)  

---

### [CVE-2021-3156](CVE-2021-3156-DASICS-ICT_DASICS-CVE-2021-3156.md) 🔴 ✅

**名称:** CVE-2021-3156 - Sudo Heap-Based Buffer Overflow  
**类型:** Heap-Based Buffer Overflow  
**风险:** 高危，可导致本地权限提升至root  
**投毒风险:** 10%  
**发现时间:** 2025-05-12  
**POC仓库:** [DASICS-CVE-2021-3156](https://github.com/DASICS-ICT/DASICS-CVE-2021-3156)  

---

### [CVE-2021-3156](CVE-2021-3156-wurwur_CVE-2021-3156.md) 🔴 ✅

**名称:** CVE-2021-3156-Sudo-Heap-Based Buffer Overflow  
**类型:** Heap-Based Buffer Overflow  
**风险:** 高危，允许本地用户提升权限至root  
**投毒风险:** 10%  
**发现时间:** 2025-05-12  
**POC仓库:** [CVE-2021-3156](https://github.com/wurwur/CVE-2021-3156)  

---

### [CVE-2021-3156](CVE-2021-3156-lypd0_CVE-2021-3156-checker.md) 🔴 ✅

**名称:** CVE-2021-3156-Sudo-Heap 缓冲区溢出  
**类型:** Heap 缓冲区溢出  
**风险:** 高危，允许本地用户提升权限至 root  
**投毒风险:** 5%  
**发现时间:** 2025-05-12  
**POC仓库:** [CVE-2021-3156-checker](https://github.com/lypd0/CVE-2021-3156-checker)  

---

### [CVE-2021-3156](CVE-2021-3156-Typical0day_CVE-2021-3156.md) 🔴 ✅

**名称:** CVE-2021-3156 (Baron Samedit)  
**类型:** 堆缓冲区溢出  
**风险:** 高危，本地用户可提升权限至root  
**投毒风险:** 5%  
**发现时间:** 2025-05-12  
**POC仓库:** [CVE-2021-3156](https://github.com/Typical0day/CVE-2021-3156)  

---

### [CVE-2021-3156](CVE-2021-3156-Bad3r_CVE-2021-3156-without-ip-command.md) 🔴 ✅

**名称:** CVE-2021-3156 (Baron Samedit) Sudo Heap-Based Buffer Overflow  
**类型:** Heap-Based Buffer Overflow  
**风险:** 高危，可导致权限提升至root  
**投毒风险:** 10%  
**发现时间:** 2025-05-12  
**POC仓库:** [CVE-2021-3156-without-ip-command](https://github.com/Bad3r/CVE-2021-3156-without-ip-command)  

---

### [CVE-2021-3156](CVE-2021-3156-Sornphut_CVE-2021-3156-Heap-Based-Buffer-Overflow-in-Sudo-Baron-Samedit-.md) 🔴 ✅

**名称:** CVE-2021-3156 - Sudo Heap-Based Buffer Overflow  
**类型:** Heap-Based Buffer Overflow  
**风险:** 高危，允许本地用户提升权限至root  
**投毒风险:** 1%  
**发现时间:** 2025-05-12  
**POC仓库:** [CVE-2021-3156-Heap-Based-Buffer-Overflow-in-Sudo-Baron-Samedit-](https://github.com/Sornphut/CVE-2021-3156-Heap-Based-Buffer-Overflow-in-Sudo-Baron-Samedit-)  

---

### [CVE-2017-8917](CVE-2017-8917-brianwrf_Joomla3.7-SQLi-CVE-2017-8917.md) 🔴 ✅

**名称:** CVE-2017-8917-Joomla-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-05-12  
**POC仓库:** [Joomla3.7-SQLi-CVE-2017-8917](https://github.com/brianwrf/Joomla3.7-SQLi-CVE-2017-8917)  

---

### [CVE-2017-8917](CVE-2017-8917-cved-sources_cve-2017-8917.md) 🔴 ✅

**名称:** CVE-2017-8917-Joomla-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-05-12  
**POC仓库:** [cve-2017-8917](https://github.com/cved-sources/cve-2017-8917)  

---

### [CVE-2017-8917](CVE-2017-8917-gmohlamo_CVE-2017-8917.md) 🔴 ✅

**名称:** CVE-2017-8917-Joomla!-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-05-12  
**POC仓库:** [CVE-2017-8917](https://github.com/gmohlamo/CVE-2017-8917)  

---

### [CVE-2017-8917](CVE-2017-8917-stefanlucas_Exploit-Joomla.md) 🔴 ✅

**名称:** CVE-2017-8917-Joomla-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-05-12  
**POC仓库:** [Exploit-Joomla](https://github.com/stefanlucas/Exploit-Joomla)  

---

### [CVE-2017-8917](CVE-2017-8917-AkuCyberSec_CVE-2017-8917-Joomla-370-SQL-Injection.md) 🔴 ✅

**名称:** CVE-2017-8917 - Joomla SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露、权限提升和服务器控制  
**投毒风险:** 0%  
**发现时间:** 2025-05-12  
**POC仓库:** [CVE-2017-8917-Joomla-370-SQL-Injection](https://github.com/AkuCyberSec/CVE-2017-8917-Joomla-370-SQL-Injection)  

---

### [CVE-2017-8917](CVE-2017-8917-Siopy_CVE-2017-8917.md) 🔴 ✅

**名称:** CVE-2017-8917 - Joomla 3.7.0 'com_fields' SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露和远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-05-12  
**POC仓库:** [CVE-2017-8917](https://github.com/Siopy/CVE-2017-8917)  

---

### [CVE-2017-8917](CVE-2017-8917-ionutbaltariu_joomla_CVE-2017-8917.md) 🔴 ✅

**名称:** CVE-2017-8917 - Joomla! SQL 注入  
**类型:** SQL 注入  
**风险:** 高危，可能导致数据泄露、数据篡改、权限提升甚至远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-05-12  
**POC仓库:** [joomla_CVE-2017-8917](https://github.com/ionutbaltariu/joomla_CVE-2017-8917)  

---

### [CVE-2017-8917](CVE-2017-8917-BaptisteContreras_CVE-2017-8917-Joomla.md) 🔴 ✅

**名称:** CVE-2017-8917-Joomla-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露和远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-05-12  
**POC仓库:** [CVE-2017-8917-Joomla](https://github.com/BaptisteContreras/CVE-2017-8917-Joomla)  

---

### [CVE-2017-8917](CVE-2017-8917-gloliveira1701_Joomblah.md) 🔴 ✅

**名称:** CVE-2017-8917-Joomla-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-05-12  
**POC仓库:** [Joomblah](https://github.com/gloliveira1701/Joomblah)  

---

### [CVE-2017-8917](CVE-2017-8917-xcalts_CVE-2017-8917.md) 🔴 ✅

**名称:** CVE-2017-8917 - Joomla! SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露、数据篡改和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-05-12  
**POC仓库:** [CVE-2017-8917](https://github.com/xcalts/CVE-2017-8917)  

---

### [CVE-2024-4577](CVE-2024-4577-gmh5225_CVE-2024-4577-PHP-RCE.md) 🔴 ✅

**名称:** CVE-2024-4577-PHP-CGI参数注入  
**类型:** OS命令注入  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-05-12  
**POC仓库:** [CVE-2024-4577-PHP-RCE](https://github.com/gmh5225/CVE-2024-4577-PHP-RCE)  

---

### [CVE-2024-4577](CVE-2024-4577-tntrock_CVE-2024-4577_PowerShell.md) 🔴 ✅

**名称:** CVE-2024-4577 - PHP-CGI Argument Injection  
**类型:** OS Command Injection/Remote Code Execution  
**风险:** 高危，允许远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-05-12  
**POC仓库:** [CVE-2024-4577_PowerShell](https://github.com/tntrock/CVE-2024-4577_PowerShell)  

---

### [CVE-2023-37582](CVE-2023-37582-Malayke_CVE-2023-37582_EXPLOIT.md) 🔴 ✅

**名称:** CVE-2023-37582-Apache RocketMQ-远程命令执行  
**类型:** 远程命令执行  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-05-12  
**POC仓库:** [CVE-2023-37582_EXPLOIT](https://github.com/Malayke/CVE-2023-37582_EXPLOIT)  

---

### [CVE-2023-37582](CVE-2023-37582-laishouchao_Apache-RocketMQ-RCE-CVE-2023-37582-poc.md) 🔴 ✅

**名称:** CVE-2023-37582-Apache RocketMQ-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-05-12  
**POC仓库:** [Apache-RocketMQ-RCE-CVE-2023-37582-poc](https://github.com/laishouchao/Apache-RocketMQ-RCE-CVE-2023-37582-poc)  

---

### [CVE-2020-24913](CVE-2020-24913-agarma_CVE-2020-24913-PoC.md) 🔴 ✅

**名称:** CVE-2020-24913-QCubed-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露  
**投毒风险:** 10%  
**发现时间:** 2025-05-11  
**POC仓库:** [CVE-2020-24913-PoC](https://github.com/agarma/CVE-2020-24913-PoC)  

---

### [CVE-2025-24813](CVE-2025-24813-fatkz_CVE-2025-24813.md) 🔴 ✅

**名称:** CVE-2025-24813 - Apache Tomcat 远程代码执行漏洞  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-05-11  
**POC仓库:** [CVE-2025-24813](https://github.com/fatkz/CVE-2025-24813)  

---

### [CVE-2025-0411](CVE-2025-0411-betulssahin_CVE-2025-0411-7-Zip-Mark-of-the-Web-Bypass.md) 🔴 ✅

**名称:** CVE-2025-0411-7-Zip Mark-of-the-Web Bypass  
**类型:** Mark-of-the-Web Bypass  
**风险:** 高危，可能导致任意代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-05-11  
**POC仓库:** [CVE-2025-0411-7-Zip-Mark-of-the-Web-Bypass](https://github.com/betulssahin/CVE-2025-0411-7-Zip-Mark-of-the-Web-Bypass)  

---

### [CVE-2023-42793](CVE-2023-42793-syaifulandy_Nuclei-Template-CVE-2023-42793.yaml.md) 🔴 ✅

**名称:** CVE-2023-42793-JetBrains TeamCity RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，未经身份验证的远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-05-11  
**POC仓库:** [Nuclei-Template-CVE-2023-42793.yaml](https://github.com/syaifulandy/Nuclei-Template-CVE-2023-42793.yaml)  

---

### [CVE-2025-31644](CVE-2025-31644-mbadanoiu_CVE-2025-31644.md) 🔴 ✅

**名称:** CVE-2025-31644-F5 BIG-IP-命令注入  
**类型:** 命令注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 2%  
**发现时间:** 2025-05-11  
**POC仓库:** [CVE-2025-31644](https://github.com/mbadanoiu/CVE-2025-31644)  

---

### [CVE-2024-21413](CVE-2024-21413-PolarisXSec_CVE-2024-21413.md)  

**名称:** CVE-2024-21413 Microsoft Outlook 远程代码执行漏洞  
**类型:** 远程代码执行 (RCE)  
**风险:** 严重，可能导致完全控制受影响的系统  
**投毒风险:** 10%  
**发现时间:** 2025-05-11  
**POC仓库:** [CVE-2024-21413](https://github.com/PolarisXSec/CVE-2024-21413)  

---

### [CVE-2025-24252](CVE-2025-24252-apwlq_AirBorne-PoC.md) 🔴 ✅

**名称:** CVE-2025-24252 - Apple AirPlay Use-After-Free RCE (AirBorne)  
**类型:** Use-After-Free  
**风险:** 高危，远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-05-11  
**POC仓库:** [AirBorne-PoC](https://github.com/apwlq/AirBorne-PoC)  

---

### [CVE-2025-24252](CVE-2025-24252-ekomsSavior_AirBorne-PoC.md) 🔴 ✅

**名称:** CVE-2025-24252-AirPlay-UAF远程代码执行  
**类型:** Use-After-Free (UAF)  
**风险:** 高危，未经身份验证的远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-05-11  
**POC仓库:** [AirBorne-PoC](https://github.com/ekomsSavior/AirBorne-PoC)  

---

### [CVE-2025-24252](CVE-2025-24252-cakescats_airborn-IOS-CVE-2025-24252.md) 🔴 ✅

**名称:** CVE-2025-24252-Apple AirPlay Use-After-Free RCE  
**类型:** Use-After-Free 远程代码执行  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-05-11  
**POC仓库:** [airborn-IOS-CVE-2025-24252](https://github.com/cakescats/airborn-IOS-CVE-2025-24252)  

---

### [CVE-2025-47810](CVE-2025-47810-ptrstr_CVE-2025-47810.md) 🔴 ✅

**名称:** CVE-2025-47810 - PunkBuster LPE  
**类型:** 本地权限提升 (LPE)  
**风险:** 高危，允许低权限用户提升至SYSTEM权限  
**投毒风险:** 10%  
**发现时间:** 2025-05-11  
**POC仓库:** [CVE-2025-47810](https://github.com/ptrstr/CVE-2025-47810)  

---

### [CVE-2025-24203](CVE-2025-24203-Ravibr87_dirtyZero.md) 🟡 ✅

**名称:** CVE-2025-24203-DirtyZero-文件系统修改  
**类型:** 文件系统权限绕过  
**风险:** 中危，可能导致文件系统被篡改  
**投毒风险:** 10%  
**发现时间:** 2025-05-10  
**POC仓库:** [dirtyZero](https://github.com/Ravibr87/dirtyZero)  

---

### [CVE-2025-32583](CVE-2025-32583-Nxploited_CVE-2025-32583.md) 🔴 ✅

**名称:** CVE-2025-32583-PDF 2 Post-RCE  
**类型:** 远程代码执行（RCE）  
**风险:** 高危，可完全控制目标网站  
**投毒风险:** 10%  
**发现时间:** 2025-05-10  
**POC仓库:** [CVE-2025-32583](https://github.com/Nxploited/CVE-2025-32583)  

---

### [CVE-2025-24203](CVE-2025-24203-BlueDiamond2021_iOS-CVE-2025-24203-Paths.md) 🟡 ✅

**名称:** CVE-2025-24203-文件系统修改  
**类型:** 文件系统权限绕过  
**风险:** 中危，应用可能修改受保护的文件系统部分  
**投毒风险:** 10%  
**发现时间:** 2025-05-10  
**POC仓库:** [iOS-CVE-2025-24203-Paths](https://github.com/BlueDiamond2021/iOS-CVE-2025-24203-Paths)  

---

### [CVE-2025-31324](CVE-2025-31324-sug4r-wr41th_CVE-2025-31324.md) 🔴 ✅

**名称:** CVE-2025-31324-SAP NetWeaver Visual Composer Metadata Uploader未授权文件上传  
**类型:** 未授权文件上传  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-05-10  
**POC仓库:** [CVE-2025-31324](https://github.com/sug4r-wr41th/CVE-2025-31324)  

---

### [CVE-2025-24203](CVE-2025-24203-jailbreakdotparty_dirtyZero.md) 🟡 ✅

**名称:** CVE-2025-24203-dirtyZero-文件系统修改  
**类型:** 文件系统修改  
**风险:** 中危，可能允许恶意应用修改受保护的文件系统区域  
**投毒风险:** 5%  
**发现时间:** 2025-05-10  
**POC仓库:** [dirtyZero](https://github.com/jailbreakdotparty/dirtyZero)  

---

### [CVE-2025-24203](CVE-2025-24203-BlueDiamond2021_iOS-CVE-2025-24203-Paths.md) 🟡 ✅

**名称:** CVE-2025-24203-文件系统修改  
**类型:** 文件系统权限绕过  
**风险:** 中危，可能导致应用修改受保护的文件系统  
**投毒风险:** 1%  
**发现时间:** 2025-05-10  
**POC仓库:** [iOS-CVE-2025-24203-Paths](https://github.com/BlueDiamond2021/iOS-CVE-2025-24203-Paths)  

---

### [CVE-2025-4403](CVE-2025-4403-Yucaerin_CVE-2025-4403.md) 🔴 ✅

**名称:** CVE-2025-4403 - Drag and Drop Multiple File Upload for WooCommerce 任意文件上传漏洞  
**类型:** 任意文件上传  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-05-10  
**POC仓库:** [CVE-2025-4403](https://github.com/Yucaerin/CVE-2025-4403)  

---

### [CVE-2017-5487](CVE-2017-5487-teambugsbunny_wpUsersScan.md)  ✅

**名称:** CVE-2017-5487 - WordPress 用户枚举  
**类型:** 信息泄露  
**风险:** 低危，泄露用户名信息，增加暴力破解密码的风险  
**投毒风险:** 0%  
**发现时间:** 2025-05-10  
**POC仓库:** [wpUsersScan](https://github.com/teambugsbunny/wpUsersScan)  

---

### [CVE-2017-5487](CVE-2017-5487-R3K1NG_wpUsersScan.md)  ✅

**名称:** CVE-2017-5487 WordPress REST API 用户枚举  
**类型:** 信息泄露  
**风险:** 低危，泄露用户名可能为后续攻击提供便利  
**投毒风险:** 0%  
**发现时间:** 2025-05-10  
**POC仓库:** [wpUsersScan](https://github.com/R3K1NG/wpUsersScan)  

---

### [CVE-2017-5487](CVE-2017-5487-GeunSam2_CVE-2017-5487.md) 🟡 ✅

**名称:** CVE-2017-5487-WordPress-信息泄露  
**类型:** 信息泄露  
**风险:** 中危，可能暴露用户名等敏感信息，为进一步攻击提供便利  
**投毒风险:** 0%  
**发现时间:** 2025-05-10  
**POC仓库:** [CVE-2017-5487](https://github.com/GeunSam2/CVE-2017-5487)  

---

### [CVE-2017-5487](CVE-2017-5487-patilkr_wp-CVE-2017-5487-exploit.md)  ✅

**名称:** CVE-2017-5487 - WordPress 用户枚举漏洞  
**类型:** 信息泄露  
**风险:** 低危，泄露用户名信息，可能辅助暴力破解  
**投毒风险:** 0%  
**发现时间:** 2025-05-10  
**POC仓库:** [wp-CVE-2017-5487-exploit](https://github.com/patilkr/wp-CVE-2017-5487-exploit)  

---

### [CVE-2017-5487](CVE-2017-5487-zkhalidul_GrabberWP-CVE-2017-5487.md) 🟡 ✅

**名称:** CVE-2017-5487-WordPress-用户枚举  
**类型:** 信息泄露/用户枚举  
**风险:** 中危，可能泄露用户名等敏感信息，为进一步攻击提供便利  
**投毒风险:** 0%  
**发现时间:** 2025-05-10  
**POC仓库:** [GrabberWP-CVE-2017-5487](https://github.com/zkhalidul/GrabberWP-CVE-2017-5487)  

---

### [CVE-2017-5487](CVE-2017-5487-SeasonLeague_CVE-2017-5487.md)  ✅

**名称:** CVE-2017-5487 - WordPress REST API 用户枚举  
**类型:** 信息泄露  
**风险:** 低危，暴露用户名可能为进一步攻击提供信息  
**投毒风险:** 0%  
**发现时间:** 2025-05-10  
**POC仓库:** [CVE-2017-5487](https://github.com/SeasonLeague/CVE-2017-5487)  

---

### [CVE-2017-5487](CVE-2017-5487-Ravindu-Priyankara_CVE-2017-5487-vulnerability-on-NSBM.md) 🟡 ✅

**名称:** CVE-2017-5487-WordPress用户枚举漏洞  
**类型:** 信息泄露  
**风险:** 中危，可能导致用户账户信息泄露  
**投毒风险:** 5%  
**发现时间:** 2025-05-10  
**POC仓库:** [CVE-2017-5487-vulnerability-on-NSBM](https://github.com/Ravindu-Priyankara/CVE-2017-5487-vulnerability-on-NSBM)  

---

### [CVE-2017-5487](CVE-2017-5487-K3ysTr0K3R_CVE-2017-5487-EXPLOIT.md)  ✅

**名称:** CVE-2017-5487-WordPress-REST API 用户枚举  
**类型:** 信息泄露  
**风险:** 低危，泄露用户名信息  
**投毒风险:** 5%  
**发现时间:** 2025-05-10  
**POC仓库:** [CVE-2017-5487-EXPLOIT](https://github.com/K3ysTr0K3R/CVE-2017-5487-EXPLOIT)  

---

### [CVE-2017-5487](CVE-2017-5487-dream434_CVE-2017-5487.md) 🟡 ✅

**名称:** CVE-2017-5487-WordPress-REST API 用户枚举  
**类型:** 信息泄露/用户枚举  
**风险:** 中危，可能泄露用户名，为后续攻击提供信息  
**投毒风险:** 5%  
**发现时间:** 2025-05-10  
**POC仓库:** [CVE-2017-5487](https://github.com/dream434/CVE-2017-5487)  

---

### [CVE-2017-5487](CVE-2017-5487-user20252228_cve-2017-5487.md)  ✅

**名称:** CVE-2017-5487 WordPress REST API 用户枚举漏洞  
**类型:** 信息泄露  
**风险:** 低危，仅暴露作者信息  
**投毒风险:** 0%  
**发现时间:** 2025-05-10  
**POC仓库:** [cve-2017-5487](https://github.com/user20252228/cve-2017-5487)  

---

### [CVE-2017-5487](CVE-2017-5487-ndr-repo_CVE-2017-5487.md)  ✅

**名称:** CVE-2017-5487-WordPress-用户信息泄露  
**类型:** 信息泄露  
**风险:** 低危，泄露用户信息  
**投毒风险:** 0%  
**发现时间:** 2025-05-10  
**POC仓库:** [CVE-2017-5487](https://github.com/ndr-repo/CVE-2017-5487)  

---

### [CVE-2025-24813](CVE-2025-24813-Eduardo-hardvester_CVE-2025-24813.md) 🔴 ✅

**名称:** CVE-2025-24813-Apache Tomcat-路径遍历/反序列化RCE  
**类型:** 路径遍历/反序列化RCE  
**风险:** 高危，可能导致远程代码执行和敏感信息泄露  
**投毒风险:** 5%  
**发现时间:** 2025-05-10  
**POC仓库:** [CVE-2025-24813](https://github.com/Eduardo-hardvester/CVE-2025-24813)  

---

### [CVE-2024-21532](CVE-2024-21532-lirantal_CVE-2024-21532-PoC-ggit.md) 🔴 ✅

**名称:** CVE-2024-21532-ggit-命令注入  
**类型:** 命令注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-05-10  
**POC仓库:** [CVE-2024-21532-PoC-ggit](https://github.com/lirantal/CVE-2024-21532-PoC-ggit)  

---

### [CVE-2024-21533](CVE-2024-21533-lirantal_CVE-2024-21533-PoC-ggit.md) 🟡 ✅

**名称:** CVE-2024-21533-ggit-参数注入  
**类型:** 参数注入  
**风险:** 中危，可能导致任意命令执行  
**投毒风险:** 10%  
**发现时间:** 2025-05-10  
**POC仓库:** [CVE-2024-21533-PoC-ggit](https://github.com/lirantal/CVE-2024-21533-PoC-ggit)  

---

### [CVE-2025-20188](CVE-2025-20188-Sratet_CVE-2025-20188.md)  

**名称:** CVE-2025-20188 - Cisco IOS XE 任意文件上传/RCE  
**类型:** 任意文件上传/远程代码执行  
**风险:** 严重，未授权远程攻击者可上传任意文件，执行任意命令并获取root权限。  
**投毒风险:** 10%  
**发现时间:** 2025-05-10  
**POC仓库:** [CVE-2025-20188](https://github.com/Sratet/CVE-2025-20188)  

---

### [CVE-2025-29306](CVE-2025-29306-congdong007_CVE-2025-29306_poc.md) 🔴 ✅

**名称:** CVE-2025-29306-FoxCMS-代码注入  
**类型:** 代码注入  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-05-10  
**POC仓库:** [CVE-2025-29306_poc](https://github.com/congdong007/CVE-2025-29306_poc)  

---

### [CVE-2023-25813](CVE-2023-25813-White-BAO_CVE-2023-25813.md) 🔴 ✅

**名称:** CVE-2023-25813-Sequelize-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露、数据篡改和远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-05-10  
**POC仓库:** [CVE-2023-25813](https://github.com/White-BAO/CVE-2023-25813)  

---

### [CVE-2023-25813](CVE-2023-25813-pbj2647_CVE-2023-25813.md) 🔴 ✅

**名称:** CVE-2023-25813-Sequelize-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露、数据篡改和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-05-10  
**POC仓库:** [CVE-2023-25813](https://github.com/pbj2647/CVE-2023-25813)  

---

### [CVE-2023-25813](CVE-2023-25813-sea-middle_cve-2023-25813.md) 🔴 ✅

**名称:** CVE-2023-25813-Sequelize-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露和远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-05-10  
**POC仓库:** [cve-2023-25813](https://github.com/sea-middle/cve-2023-25813)  

---

### [CVE-2023-25813](CVE-2023-25813-wxuycea_CVE-2023-25813.md) 🔴 ✅

**名称:** CVE-2023-25813-Sequelize-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露和远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-05-10  
**POC仓库:** [CVE-2023-25813](https://github.com/wxuycea/CVE-2023-25813)  

---

### [CVE-2023-25813](CVE-2023-25813-bde574786_Sequelize-1day-CVE-2023-25813.md) 🔴 ✅

**名称:** CVE-2023-25813-Sequelize-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露、数据篡改和远程代码执行（取决于数据库权限）  
**投毒风险:** 10%  
**发现时间:** 2025-05-10  
**POC仓库:** [Sequelize-1day-CVE-2023-25813](https://github.com/bde574786/Sequelize-1day-CVE-2023-25813)  

---

### [CVE-2024-28752](CVE-2024-28752-ReaJason_CVE-2024-28752.md) 🔴 ✅

**名称:** CVE-2024-28752-Apache CXF-SSRF  
**类型:** SSRF  
**风险:** 高危，可能导致敏感信息泄露，内网扫描，甚至在某些情况下可以进行远程代码执行（取决于内网环境和可访问的资源）。  
**投毒风险:** 5%  
**发现时间:** 2025-05-10  
**POC仓库:** [CVE-2024-28752](https://github.com/ReaJason/CVE-2024-28752)  

---

### [CVE-2025-21307](CVE-2025-21307-git-account7_CVE-2025-21307.md) 🔴 

**名称:** CVE-2025-21307 Windows Reliable Multicast Transport Driver (RMCAST) 远程代码执行漏洞  
**类型:** 远程代码执行  
**风险:** 高危，允许未经身份验证的远程攻击者在受影响的Windows系统上执行任意代码  
**投毒风险:** 95%  
**发现时间:** 2025-05-10  
**POC仓库:** [CVE-2025-21307](https://github.com/git-account7/CVE-2025-21307)  

---

### [CVE-2025-3605](CVE-2025-3605-Nxploited_CVE-2025-3605.md)  ✅

**名称:** CVE-2025-3605 - Frontend Login and Registration Blocks - 权限提升  
**类型:** 权限提升  
**风险:** 严重，攻击者可以更改任意用户的电子邮件地址，包括管理员，并利用该地址重置用户的密码并获得对其帐户的访问权限。  
**投毒风险:** 0%  
**发现时间:** 2025-05-10  
**POC仓库:** [CVE-2025-3605](https://github.com/Nxploited/CVE-2025-3605)  

---

### [CVE-2017-5638](CVE-2017-5638-toothbrushsoapflannelbiscuits_cve-2017-5638.md) 🔴 ✅

**名称:** CVE-2017-5638-Apache Struts2-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-05-09  
**POC仓库:** [cve-2017-5638](https://github.com/toothbrushsoapflannelbiscuits/cve-2017-5638)  

---

### [CVE-2024-25600](CVE-2024-25600-DedsecTeam-BlackHat_Poleposph.md) 🔴 ✅

**名称:** CVE-2024-25600-Bricks Builder-代码注入  
**类型:** 代码注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-05-09  
**POC仓库:** [Poleposph](https://github.com/DedsecTeam-BlackHat/Poleposph)  

---

### [CVE-2024-38475](CVE-2024-38475-syaifulandy_CVE-2024-38475.md) 🔴 ✅

**名称:** CVE-2024-38475 - Apache HTTP Server mod_rewrite 不当转义漏洞  
**类型:** 路径遍历/代码执行/源码泄露  
**风险:** 高危，可能导致代码执行或源码泄露  
**投毒风险:** 10%  
**发现时间:** 2025-05-09  
**POC仓库:** [CVE-2024-38475](https://github.com/syaifulandy/CVE-2024-38475)  

---

### [CVE-2025-27533](CVE-2025-27533-absholi7ly_CVE-2025-27533-Exploit-for-Apache-ActiveMQ.md) 🟡 ✅

**名称:** CVE-2025-27533-Apache ActiveMQ-内存分配拒绝服务  
**类型:** 拒绝服务 (DoS)  
**风险:** 中危，可能导致服务中断  
**投毒风险:** 1%  
**发现时间:** 2025-05-09  
**POC仓库:** [CVE-2025-27533-Exploit-for-Apache-ActiveMQ](https://github.com/absholi7ly/CVE-2025-27533-Exploit-for-Apache-ActiveMQ)  

---

### [CVE-2024-13513](CVE-2024-13513-KTN1990_CVE-2024-13513.md) 🔴 ✅

**名称:** CVE-2024-13513 - Oliver POS 敏感信息泄露导致权限提升  
**类型:** 敏感信息泄露 / 权限提升  
**风险:** 高危，可能导致站点完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-05-09  
**POC仓库:** [CVE-2024-13513](https://github.com/KTN1990/CVE-2024-13513)  

---

### [CVE-2025-47549](CVE-2025-47549-d0n601_CVE-2025-47549.md) 🔴 ✅

**名称:** CVE-2025-47549-WordPress BEAF-任意文件上传  
**类型:** 任意文件上传  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-05-08  
**POC仓库:** [CVE-2025-47549](https://github.com/d0n601/CVE-2025-47549)  

---

### [CVE-2021-25646](CVE-2021-25646-j2ekim_CVE-2021-25646.md) 🔴 ✅

**名称:** CVE-2021-25646-Apache Druid-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可导致服务器被完全控制  
**投毒风险:** 5%  
**发现时间:** 2025-05-08  
**POC仓库:** [CVE-2021-25646](https://github.com/j2ekim/CVE-2021-25646)  

---

### [CVE-2025-47550](CVE-2025-47550-d0n601_CVE-2025-47550.md) 🔴 ✅

**名称:** CVE-2025-47550-Instantio-WordPress插件-任意文件上传  
**类型:** 任意文件上传  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-05-08  
**POC仓库:** [CVE-2025-47550](https://github.com/d0n601/CVE-2025-47550)  

---

### [CVE-2021-25646](CVE-2021-25646-yaunsky_cve-2021-25646.md) 🔴 ✅

**名称:** CVE-2021-25646-Apache Druid 远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，允许经过身份验证的用户执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-05-08  
**POC仓库:** [cve-2021-25646](https://github.com/yaunsky/cve-2021-25646)  

---

### [CVE-2021-25646](CVE-2021-25646-lp008_CVE-2021-25646.md) 🔴 ✅

**名称:** CVE-2021-25646 Apache Druid RCE  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-05-08  
**POC仓库:** [CVE-2021-25646](https://github.com/lp008/CVE-2021-25646)  

---

### [CVE-2021-25646](CVE-2021-25646-Ormicron_CVE-2021-25646-GUI.md) 🔴 ✅

**名称:** CVE-2021-25646-Apache Druid-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 20%  
**发现时间:** 2025-05-08  
**POC仓库:** [CVE-2021-25646-GUI](https://github.com/Ormicron/CVE-2021-25646-GUI)  

---

### [CVE-2021-25646](CVE-2021-25646-givemefivw_CVE-2021-25646.md) 🔴 ✅

**名称:** CVE-2021-25646-ApacheDruid远程命令执行  
**类型:** 远程代码执行  
**风险:** 高危，可完全控制服务器  
**投毒风险:** 0%  
**发现时间:** 2025-05-08  
**POC仓库:** [CVE-2021-25646](https://github.com/givemefivw/CVE-2021-25646)  

---

### [CVE-2021-25646](CVE-2021-25646-Vulnmachines_Apache-Druid-CVE-2021-25646.md) 🔴 ✅

**名称:** CVE-2021-25646-Apache Druid-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-05-08  
**POC仓库:** [Apache-Druid-CVE-2021-25646](https://github.com/Vulnmachines/Apache-Druid-CVE-2021-25646)  

---

### [CVE-2021-25646](CVE-2021-25646-1n7erface_PocList.md) 🔴 ✅

**名称:** CVE-2021-25646-Apache Druid-RCE  
**类型:** 远程代码执行  
**风险:** 高危，可导致服务器被完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-05-08  
**POC仓库:** [PocList](https://github.com/1n7erface/PocList)  

---

### [CVE-2021-25646](CVE-2021-25646-k7pro_CVE-2021-25646-exp.md) 🔴 ✅

**名称:** CVE-2021-25646-Apache Druid 远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-05-08  
**POC仓库:** [CVE-2021-25646-exp](https://github.com/k7pro/CVE-2021-25646-exp)  

---

### [CVE-2021-25646](CVE-2021-25646-gps1949_CVE-2021-25646.md) 🔴 ✅

**名称:** CVE-2021-25646 - Apache Druid 远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，允许攻击者在Druid服务器上执行任意代码  
**投毒风险:** 5%  
**发现时间:** 2025-05-08  
**POC仓库:** [CVE-2021-25646](https://github.com/gps1949/CVE-2021-25646)  

---

### [CVE-2021-25646](CVE-2021-25646-tiemio_RCE-PoC-CVE-2021-25646.md) 🔴 ✅

**名称:** CVE-2021-25646-Apache Druid-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-05-08  
**POC仓库:** [RCE-PoC-CVE-2021-25646](https://github.com/tiemio/RCE-PoC-CVE-2021-25646)  

---

### [CVE-2021-42392](CVE-2021-42392-cybersecurityworks553_CVE-2021-42392-Detect.md) 🔴 ✅

**名称:** CVE-2021-42392 - H2 Database Console RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，未经身份验证的远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-05-08  
**POC仓库:** [CVE-2021-42392-Detect](https://github.com/cybersecurityworks553/CVE-2021-42392-Detect)  

---

### [CVE-2021-42392](CVE-2021-42392-Be-Innova_CVE-2021-42392-exploit-lab.md) 🔴 ✅

**名称:** CVE-2021-42392-H2数据库-JNDI注入/远程代码执行  
**类型:** JNDI注入/远程代码执行  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-05-08  
**POC仓库:** [CVE-2021-42392-exploit-lab](https://github.com/Be-Innova/CVE-2021-42392-exploit-lab)  

---

### [CVE-2024-6648](CVE-2024-6648-n0d0n_CVE-2024-6648.md) 🔴 ✅

**名称:** CVE-2024-6648-AP Page Builder-路径遍历  
**类型:** 路径遍历  
**风险:** 高危，可能导致敏感文件泄露  
**投毒风险:** 0%  
**发现时间:** 2025-05-08  
**POC仓库:** [CVE-2024-6648](https://github.com/n0d0n/CVE-2024-6648)  

---

### [CVE-2024-39719](CVE-2024-39719-srcx404_CVE-2024-39719.md) 🟡 ✅

**名称:** CVE-2024-39719-Ollama-文件存在性泄露  
**类型:** 文件存在性泄露  
**风险:** 中危，可用于探测服务器上的敏感文件  
**投毒风险:** 0%  
**发现时间:** 2025-05-08  
**POC仓库:** [CVE-2024-39719](https://github.com/srcx404/CVE-2024-39719)  

---

### [CVE-2023-7231](CVE-2023-7231-BBO513_CVE-2023-7231.md) 🔴 

**名称:** CVE-2023-7231 Memcached RCE via Gopher  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 30%  
**发现时间:** 2025-05-08  
**POC仓库:** [CVE-2023-7231](https://github.com/BBO513/CVE-2023-7231)  

---

### [CVE-2025-29927](CVE-2025-29927-EarthAngel666_x-middleware-exploit.md) 🔴 ✅

**名称:** CVE-2025-29927-Next.js-中间件鉴权绕过  
**类型:** 鉴权绕过  
**风险:** 高危，可能导致未授权访问  
**投毒风险:** 0%  
**发现时间:** 2025-05-08  
**POC仓库:** [x-middleware-exploit](https://github.com/EarthAngel666/x-middleware-exploit)  

---

### [CVE-2025-31324](CVE-2025-31324-nairuzabulhul_nuclei-template-cve-2025-31324-check.md) 🔴 ✅

**名称:** CVE-2025-31324 - SAP NetWeaver Visual Composer 未授权文件上传  
**类型:** 文件上传漏洞  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-05-08  
**POC仓库:** [nuclei-template-cve-2025-31324-check](https://github.com/nairuzabulhul/nuclei-template-cve-2025-31324-check)  

---

### [CVE-2018-19664](CVE-2018-19664-h31md4llr_libjpeg_cve-2018-19664.md) 🟡 ✅

**名称:** CVE-2018-19664 - libjpeg-turbo 堆缓冲区过度读取  
**类型:** 堆缓冲区过度读取  
**风险:** 中危，可能导致信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-05-08  
**POC仓库:** [libjpeg_cve-2018-19664](https://github.com/h31md4llr/libjpeg_cve-2018-19664)  

---

### [CVE-2024-57376](CVE-2024-57376-DelspoN_CVE-2024-57376.md) 🔴 ✅

**名称:** CVE-2024-57376 - D-Link DSR系列路由器 缓冲区溢出  
**类型:** 缓冲区溢出  
**风险:** 高危，允许未经身份验证的用户执行远程代码执行。  
**投毒风险:** 0%  
**发现时间:** 2025-05-08  
**POC仓库:** [CVE-2024-57376](https://github.com/DelspoN/CVE-2024-57376)  

---

### [CVE-2022-41741](CVE-2022-41741-dumbbutt0_evilMP4.md) 🔴 ✅

**名称:** CVE-2022-41741-NGINX-内存损坏  
**类型:** 内存损坏  
**风险:** 高危，可能导致Nginx工作进程崩溃或潜在的其他影响  
**投毒风险:** 5%  
**发现时间:** 2025-05-08  
**POC仓库:** [evilMP4](https://github.com/dumbbutt0/evilMP4)  

---

### [CVE-2022-41741](CVE-2022-41741-moften_CVE-2022-41741-742-Nginx-Vulnerability-Scanner.md) 🔴 ✅

**名称:** CVE-2022-41741 - Nginx ngx_http_mp4_module 内存损坏漏洞  
**类型:** 内存损坏  
**风险:** 高危，可能导致Nginx工作进程崩溃或潜在的其他影响  
**投毒风险:** 10%  
**发现时间:** 2025-05-08  
**POC仓库:** [CVE-2022-41741-742-Nginx-Vulnerability-Scanner](https://github.com/moften/CVE-2022-41741-742-Nginx-Vulnerability-Scanner)  

---

### [CVE-2025-46271](CVE-2025-46271-1Altruist_CVE-2025-46271-Reverse-Shell-PoC.md) 🔴 

**名称:** CVE-2025-46271-UNI-NMS-Lite-命令注入  
**类型:** 命令注入  
**风险:** 高危，可能允许未经身份验证的攻击者读取或操纵设备数据  
**投毒风险:** 0%  
**发现时间:** 2025-05-07  
**POC仓库:** [CVE-2025-46271-Reverse-Shell-PoC](https://github.com/1Altruist/CVE-2025-46271-Reverse-Shell-PoC)  

---

### [CVE-2024-34463](CVE-2024-34463-yash-chandna_CVE-2024-34463.md) 🟡 ✅

**名称:** CVE-2024-34463 - BPL Personal Weighing Scale 蓝牙数据泄露  
**类型:** 信息泄露  
**风险:** 中危，可能导致个人体重等敏感信息泄露  
**投毒风险:** 5%  
**发现时间:** 2025-05-07  
**POC仓库:** [CVE-2024-34463](https://github.com/yash-chandna/CVE-2024-34463)  

---

### [CVE-2025-28073](CVE-2025-28073-mLniumm_CVE-2025-28073.md) 🟡 ✅

**名称:** CVE-2025-28073-phpList-Reflected XSS  
**类型:** Reflected XSS  
**风险:** 中危，可能导致会话劫持、凭据盗窃、钓鱼攻击和任意JavaScript执行  
**投毒风险:** 10%  
**发现时间:** 2025-05-07  
**POC仓库:** [CVE-2025-28073](https://github.com/mLniumm/CVE-2025-28073)  

---

### [CVE-2025-28074](CVE-2025-28074-mLniumm_CVE-2025-28074.md) 🟡 ✅

**名称:** CVE-2025-28074-phpList-XSS  
**类型:** 跨站脚本 (XSS)  
**风险:** 中危，可能导致凭据盗窃、会话劫持或恶意重定向  
**投毒风险:** 10%  
**发现时间:** 2025-05-07  
**POC仓库:** [CVE-2025-28074](https://github.com/mLniumm/CVE-2025-28074)  

---

### [CVE-2023-41425](CVE-2023-41425-heraclitan_CVE-2023-41425-WonderCMS-XSS-RCE.md) 🔴 ✅

**名称:** CVE-2023-41425 - WonderCMS XSS to RCE  
**类型:** 跨站脚本攻击 (XSS) -> 远程代码执行 (RCE)  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-05-07  
**POC仓库:** [CVE-2023-41425-WonderCMS-XSS-RCE](https://github.com/heraclitan/CVE-2023-41425-WonderCMS-XSS-RCE)  

---

### [CVE-2025-45250](CVE-2025-45250-xp3s_CVE-2025-45250.md) 🟡 ✅

**名称:** CVE-2025-45250-MrDoc-SSRF  
**类型:** SSRF (服务器端请求伪造)  
**风险:** 中危，可能导致信息泄露，内网探测，甚至远程代码执行 (如果内网服务存在漏洞)  
**投毒风险:** 10%  
**发现时间:** 2025-05-07  
**POC仓库:** [CVE-2025-45250](https://github.com/xp3s/CVE-2025-45250)  

---

### [CVE-2025-45250](CVE-2025-45250-Anike-x_CVE-2025-45250.md) 🟡 ✅

**名称:** CVE-2025-45250-MrDoc-SSRF  
**类型:** SSRF  
**风险:** 中危，可能泄露内部信息或攻击内部服务  
**投毒风险:** 0%  
**发现时间:** 2025-05-07  
**POC仓库:** [CVE-2025-45250](https://github.com/Anike-x/CVE-2025-45250)  

---

### [CVE-2025-25014](CVE-2025-25014-Sratet_CVE-2025-25014.md) 🔴 

**名称:** CVE-2025-25014 - Kibana Prototype Pollution RCE  
**类型:** Prototype Pollution  
**风险:** 高危，可导致任意代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-05-07  
**POC仓库:** [CVE-2025-25014](https://github.com/Sratet/CVE-2025-25014)  

---

### [CVE-2025-4190](CVE-2025-4190-Nxploited_CVE-2025-4190.md) 🔴 ✅

**名称:** CVE-2025-4190 - WordPress CSV Mass Importer <= 1.2 任意文件上传  
**类型:** 任意文件上传  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-05-07  
**POC仓库:** [CVE-2025-4190](https://github.com/Nxploited/CVE-2025-4190)  

---

### [CVE-2024-13800](CVE-2024-13800-RandomRobbieBF_CVE-2024-13800.md) 🔴 ✅

**名称:** CVE-2024-13800-ConvertPlus-权限绕过导致DoS  
**类型:** 权限绕过  
**风险:** 高危，可能导致拒绝服务  
**投毒风险:** 0%  
**发现时间:** 2025-05-07  
**POC仓库:** [CVE-2024-13800](https://github.com/RandomRobbieBF/CVE-2024-13800)  

---

### [CVE-2024-39722](CVE-2024-39722-srcx404_CVE-2024-39722.md) 🔴 ✅

**名称:** CVE-2024-39722-Ollama-路径遍历  
**类型:** 路径遍历  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 1%  
**发现时间:** 2025-05-07  
**POC仓库:** [CVE-2024-39722](https://github.com/srcx404/CVE-2024-39722)  

---

### [CVE-2025-31125](CVE-2025-31125-0xgh057r3c0n_CVE-2025-31125.md) 🟡 ✅

**名称:** CVE-2025-31125-Vite-Arbitrary File Read  
**类型:** 任意文件读取  
**风险:** 中危，可能导致敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-05-07  
**POC仓库:** [CVE-2025-31125](https://github.com/0xgh057r3c0n/CVE-2025-31125)  

---

### [CVE-2025-31324](CVE-2025-31324-NULLTRACE0X_CVE-2025-31324.md) 🔴 ✅

**名称:** CVE-2025-31324-SAP NetWeaver Visual Composer Metadata Uploader 未授权文件上传  
**类型:** 未授权文件上传  
**风险:** 高危，可导致远程代码执行和系统完全控制  
**投毒风险:** 5%  
**发现时间:** 2025-05-07  
**POC仓库:** [CVE-2025-31324](https://github.com/NULLTRACE0X/CVE-2025-31324)  

---

### [CVE-2022-23940](CVE-2022-23940-manuelz120_CVE-2022-23940.md) 🔴 ✅

**名称:** CVE-2022-23940 - SuiteCRM 远程代码执行  
**类型:** PHP反序列化漏洞导致远程代码执行  
**风险:** 高危，允许攻击者执行任意代码，完全控制服务器  
**投毒风险:** 10%  
**发现时间:** 2025-05-07  
**POC仓库:** [CVE-2022-23940](https://github.com/manuelz120/CVE-2022-23940)  

---

### [CVE-2025-47423](CVE-2025-47423-Haluka92_CVE-2025-47423.md) 🔴 ✅

**名称:** CVE-2025-47423 - Personal Weather Station Dashboard LFI  
**类型:** 本地文件包含 (LFI)  
**风险:** 高危，可能导致敏感信息泄露，中间人攻击，服务器伪造  
**投毒风险:** 5%  
**发现时间:** 2025-05-07  
**POC仓库:** [CVE-2025-47423](https://github.com/Haluka92/CVE-2025-47423)  

---

### [CVE-2025-27007](CVE-2025-27007-absholi7ly_CVE-2025-27007-OttoKit-exploit.md) 🔴 ✅

**名称:** CVE-2025-27007-SureTriggers-权限提升  
**类型:** 权限提升  
**风险:** 高危，可能导致管理员权限被非法获取  
**投毒风险:** 10%  
**发现时间:** 2025-05-07  
**POC仓库:** [CVE-2025-27007-OttoKit-exploit](https://github.com/absholi7ly/CVE-2025-27007-OttoKit-exploit)  

---

### [CVE-2017-14980](CVE-2017-14980-TheDarthMole_CVE-2017-14980.md) 🔴 ✅

**名称:** CVE-2017-14980-Sync Breeze Enterprise-缓冲区溢出  
**类型:** 缓冲区溢出  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-05-07  
**POC仓库:** [CVE-2017-14980](https://github.com/TheDarthMole/CVE-2017-14980)  

---

### [CVE-2017-14980](CVE-2017-14980-xn0kkx_Exploit_Sync_Breeze_v10.0.28_CVE-2017-14980.md) 🔴 ✅

**名称:** CVE-2017-14980-Sync Breeze Enterprise-缓冲区溢出  
**类型:** 缓冲区溢出  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-05-07  
**POC仓库:** [Exploit_Sync_Breeze_v10.0.28_CVE-2017-14980](https://github.com/xn0kkx/Exploit_Sync_Breeze_v10.0.28_CVE-2017-14980)  

---

### [CVE-2017-14980](CVE-2017-14980-LipeOzyy_CVE-2017-14980_syncbreeze_10.0.28_bof.md) 🔴 ✅

**名称:** CVE-2017-14980-Sync Breeze Enterprise-缓冲区溢出  
**类型:** 缓冲区溢出  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-05-07  
**POC仓库:** [CVE-2017-14980_syncbreeze_10.0.28_bof](https://github.com/LipeOzyy/CVE-2017-14980_syncbreeze_10.0.28_bof)  

---

### [CVE-2024-38475](CVE-2024-38475-p0in7s_CVE-2024-38475.md) 🔴 ✅

**名称:** CVE-2024-38475-Apache HTTP Server-mod_rewrite不当转义  
**类型:** 代码执行/源码泄露  
**风险:** 高危，可能导致代码执行和源码泄露  
**投毒风险:** 0%  
**发现时间:** 2025-05-07  
**POC仓库:** [CVE-2024-38475](https://github.com/p0in7s/CVE-2024-38475)  

---

### [CVE-2024-38475](CVE-2024-38475-soltanali0_CVE-2024-38475.md) 🔴 ✅

**名称:** CVE-2024-38475-Apache-mod_rewrite文件读取/代码执行  
**类型:** 文件读取/代码执行  
**风险:** 高危，可能导致源代码泄露和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-05-07  
**POC仓库:** [CVE-2024-38475](https://github.com/soltanali0/CVE-2024-38475)  

---

### [CVE-2024-38475](CVE-2024-38475-abrewer251_CVE-2024-38475_SonicBoom_Apache_URL_Traversal_PoC.md) 🔴 ✅

**名称:** CVE-2024-38475_SonicBoom_Apache_URL_Traversal  
**类型:** URL 路径遍历  
**风险:** 高危，可能导致代码执行或源代码泄露  
**投毒风险:** 1%  
**发现时间:** 2025-05-07  
**POC仓库:** [CVE-2024-38475_SonicBoom_Apache_URL_Traversal_PoC](https://github.com/abrewer251/CVE-2024-38475_SonicBoom_Apache_URL_Traversal_PoC)  

---

### [CVE-2025-1974](CVE-2025-1974-abrewer251_CVE-2025-1974_IngressNightmare_PoC.md) 🔴 ✅

**名称:** CVE-2025-1974_IngressNightmare  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致集群范围内的Secrets泄露和完全控制  
**投毒风险:** 5%  
**发现时间:** 2025-05-07  
**POC仓库:** [CVE-2025-1974_IngressNightmare_PoC](https://github.com/abrewer251/CVE-2025-1974_IngressNightmare_PoC)  

---

### [CVE-2025-29927](CVE-2025-29927-moften_CVE-2025-29927.md) 🔴 ✅

**名称:** CVE-2025-29927 - Next.js Middleware 认证绕过  
**类型:** 认证绕过  
**风险:** 高危，可能导致未授权访问和数据泄露  
**投毒风险:** 0%  
**发现时间:** 2025-05-06  
**POC仓库:** [CVE-2025-29927](https://github.com/moften/CVE-2025-29927)  

---

### [CVE-2024-36401](CVE-2024-36401-lowsuet_CVE-2024-36401.md) 🔴 ✅

**名称:** CVE-2024-36401-GeoServer-RCE  
**类型:** 远程代码执行  
**风险:** 高危，未经身份验证的远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-05-06  
**POC仓库:** [CVE-2024-36401](https://github.com/lowsuet/CVE-2024-36401)  

---

### [CVE-2025-2011](CVE-2025-2011-datagoboom_CVE-2025-2011.md) 🔴 ✅

**名称:** CVE-2025-2011 - Depicter Slider & Popup Builder Plugin SQL注入  
**类型:** SQL注入  
**风险:** 高危，未授权攻击者可能利用此漏洞从数据库中提取敏感信息  
**投毒风险:** 10%  
**发现时间:** 2025-05-06  
**POC仓库:** [CVE-2025-2011](https://github.com/datagoboom/CVE-2025-2011)  

---

### [CVE-2019-20372](CVE-2019-20372-vuongnv3389-sec_CVE-2019-20372.md) 🟡 ✅

**名称:** CVE-2019-20372-NGINX-HTTP请求走私  
**类型:** HTTP请求走私  
**风险:** 中危，可能导致未授权访问和信息泄露  
**投毒风险:** 5%  
**发现时间:** 2025-05-06  
**POC仓库:** [CVE-2019-20372](https://github.com/vuongnv3389-sec/CVE-2019-20372)  

---

### [CVE-2019-20372](CVE-2019-20372-0xleft_CVE-2019-20372.md) 🟡 ✅

**名称:** CVE-2019-20372-NGINX HTTP Request Smuggling  
**类型:** HTTP Request Smuggling  
**风险:** 中危，可能导致未授权访问  
**投毒风险:** 0%  
**发现时间:** 2025-05-06  
**POC仓库:** [CVE-2019-20372](https://github.com/0xleft/CVE-2019-20372)  

---

### [CVE-2019-20372](CVE-2019-20372-moften_CVE-2019-20372.md) 🟡 ✅

**名称:** CVE-2019-20372-Nginx HTTP Request Smuggling  
**类型:** HTTP Request Smuggling  
**风险:** 中危，可能导致未授权访问  
**投毒风险:** 0%  
**发现时间:** 2025-05-06  
**POC仓库:** [CVE-2019-20372](https://github.com/moften/CVE-2019-20372)  

---

### [CVE-2021-23017](CVE-2021-23017-ShivamDey_CVE-2021-23017.md) 🔴 ✅

**名称:** CVE-2021-23017-Nginx Resolver 内存覆盖  
**类型:** 内存覆盖  
**风险:** 高危，可能导致worker进程崩溃或潜在的其他影响  
**投毒风险:** 0%  
**发现时间:** 2025-05-06  
**POC仓库:** [CVE-2021-23017](https://github.com/ShivamDey/CVE-2021-23017)  

---

### [CVE-2021-23017](CVE-2021-23017-niandy_nginx-patch.md) 🔴 ✅

**名称:** CVE-2021-23017-Nginx Resolver Memory Overwrite  
**类型:** 内存覆盖  
**风险:** 高危，可能导致worker进程崩溃或潜在的其他影响  
**投毒风险:** 10%  
**发现时间:** 2025-05-06  
**POC仓库:** [nginx-patch](https://github.com/niandy/nginx-patch)  

---

### [CVE-2021-23017](CVE-2021-23017-lakshit1212_CVE-2021-23017-PoC.md) 🔴 ✅

**名称:** CVE-2021-23017-Nginx Resolver 内存覆盖漏洞  
**类型:** 内存覆盖  
**风险:** 高危，可能导致worker进程崩溃或潜在的其他影响  
**投毒风险:** 0%  
**发现时间:** 2025-05-06  
**POC仓库:** [CVE-2021-23017-PoC](https://github.com/lakshit1212/CVE-2021-23017-PoC)  

---

### [CVE-2021-23017](CVE-2021-23017-M507_CVE-2021-23017-PoC.md) 🔴 ✅

**名称:** CVE-2021-23017-Nginx Resolver 内存覆盖漏洞  
**类型:** 内存覆盖  
**风险:** 高危，可能导致worker进程崩溃或潜在其他影响  
**投毒风险:** 10%  
**发现时间:** 2025-05-06  
**POC仓库:** [CVE-2021-23017-PoC](https://github.com/M507/CVE-2021-23017-PoC)  

---

### [CVE-2021-23017](CVE-2021-23017-z3usx01_CVE-2021-23017-POC.md) 🟡 ✅

**名称:** CVE-2021-23017-Nginx Resolver 1-byte内存覆盖  
**类型:** 内存覆盖  
**风险:** 中危，可能导致worker进程崩溃或潜在的其他影响  
**投毒风险:** 1%  
**发现时间:** 2025-05-06  
**POC仓库:** [CVE-2021-23017-POC](https://github.com/z3usx01/CVE-2021-23017-POC)  

---

### [CVE-2021-23017](CVE-2021-23017-lukwagoasuman_-home-lukewago-Downloads-CVE-2021-23017-Nginx-1.14.md) 🟡 ✅

**名称:** CVE-2021-23017-Nginx Resolver 1-byte内存覆盖  
**类型:** 内存覆盖  
**风险:** 中危，可能导致worker进程崩溃或潜在的其他影响  
**投毒风险:** 10%  
**发现时间:** 2025-05-06  
**POC仓库:** [-home-lukewago-Downloads-CVE-2021-23017-Nginx-1.14](https://github.com/lukwagoasuman/-home-lukewago-Downloads-CVE-2021-23017-Nginx-1.14)  

---

### [CVE-2021-23017](CVE-2021-23017-Cybervixy_Vulnerability-Management.md) 🔴 ✅

**名称:** CVE-2021-23017-Nginx Resolver 内存覆盖  
**类型:** 内存覆盖  
**风险:** 高危，可能导致worker进程崩溃或潜在的其他影响，如DoS  
**投毒风险:** 10%  
**发现时间:** 2025-05-06  
**POC仓库:** [Vulnerability-Management](https://github.com/Cybervixy/Vulnerability-Management)  

---

### [CVE-2021-23017](CVE-2021-23017-moften_CVE-2021-23017.md) 🟡 ✅

**名称:** CVE-2021-23017-Nginx Resolver 内存覆盖  
**类型:** 内存覆盖  
**风险:** 中危，可能导致worker进程崩溃或潜在的其他影响。  
**投毒风险:** 10%  
**发现时间:** 2025-05-06  
**POC仓库:** [CVE-2021-23017](https://github.com/moften/CVE-2021-23017)  

---

### [CVE-2025-31324](CVE-2025-31324-rf-peixoto_sap_netweaver_cve-2025-31324-.md) 🔴 ✅

**名称:** CVE-2025-31324-SAP NetWeaver Visual Composer-未授权文件上传  
**类型:** 未授权文件上传  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-05-06  
**POC仓库:** [sap_netweaver_cve-2025-31324-](https://github.com/rf-peixoto/sap_netweaver_cve-2025-31324-)  

---

### [CVE-2025-34028](CVE-2025-34028-Mattb709_CVE-2025-34028-PoC-Commvault-RCE.md)  ✅

**名称:** CVE-2025-34028 - Commvault Command Center Remote Code Execution  
**类型:** 路径遍历导致的远程代码执行  
**风险:** 严重，未经身份验证的远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-05-06  
**POC仓库:** [CVE-2025-34028-PoC-Commvault-RCE](https://github.com/Mattb709/CVE-2025-34028-PoC-Commvault-RCE)  

---

### [CVE-2025-29927](CVE-2025-29927-0xpr4bin_vulnerable-next_js_cve-2025-29927.md) 🔴 ✅

**名称:** CVE-2025-29927-Next.js-Middleware-Bypass  
**类型:** 权限绕过  
**风险:** 高危，可能导致未授权访问管理后台及数据泄露  
**投毒风险:** 10%  
**发现时间:** 2025-05-06  
**POC仓库:** [vulnerable-next_js_cve-2025-29927](https://github.com/0xpr4bin/vulnerable-next_js_cve-2025-29927)  

---

### [CVE-2025-45250](CVE-2025-45250-Anike-x_CVE-2025-45250.md) 🟡 ✅

**名称:** CVE-2025-45250  
**类型:** 信息泄露  
**风险:** 中危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-05-06  
**POC仓库:** [CVE-2025-45250](https://github.com/Anike-x/CVE-2025-45250)  

---

### [CVE-2023-45878](CVE-2023-45878-ulricvbs_gibbonlms-filewrite_rce.md) 🔴 ✅

**名称:** CVE-2023-45878-GibbonEdu-任意文件写入/RCE  
**类型:** 任意文件写入/远程代码执行  
**风险:** 高危，可导致服务器被完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-05-06  
**POC仓库:** [gibbonlms-filewrite_rce](https://github.com/ulricvbs/gibbonlms-filewrite_rce)  

---

### [CVE-2002-2154](CVE-2002-2154-Hirainsingadia_CVE-2002-2154.md) 🔴 ✅

**名称:** CVE-2002-2154 Monkey HTTP Daemon 0.1.4 目录遍历漏洞  
**类型:** 目录遍历  
**风险:** 高危，可能导致敏感文件泄露  
**投毒风险:** 0%  
**发现时间:** 2025-05-06  
**POC仓库:** [CVE-2002-2154](https://github.com/Hirainsingadia/CVE-2002-2154)  

---

### [CVE-2004-0789](CVE-2004-0789-HimmeL-Byte_CVE-2004-0789-DDOS.md) 🔴 ✅

**名称:** CVE-2004-0789-DNS Response Flooding Denial of Service  
**类型:** 拒绝服务 (DoS)  
**风险:** 高危，导致CPU和网络带宽耗尽，使DNS服务器无法响应合法请求。  
**投毒风险:** 0%  
**发现时间:** 2025-05-06  
**POC仓库:** [CVE-2004-0789-DDOS](https://github.com/HimmeL-Byte/CVE-2004-0789-DDOS)  

---

### [CVE-2025-2704](CVE-2025-2704-KernelKraze_CVE-2025-2704.md) 🔴 ✅

**名称:** CVE-2025-2704-OpenVPN-拒绝服务  
**类型:** 拒绝服务 (DoS)  
**风险:** 高危，可能导致OpenVPN服务不可用  
**投毒风险:** 10%  
**发现时间:** 2025-05-06  
**POC仓库:** [CVE-2025-2704](https://github.com/KernelKraze/CVE-2025-2704)  

---

### [CVE-2025-34028](CVE-2025-34028-becrevex_Commvault-CVE-2025-34028.md) 🔴 ✅

**名称:** CVE-2025-34028-Commvault-RCE  
**类型:** 远程代码执行  
**风险:** 高危，未授权远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-05-06  
**POC仓库:** [Commvault-CVE-2025-34028](https://github.com/becrevex/Commvault-CVE-2025-34028)  

---

### [CVE-2024-48197](CVE-2024-48197-GCatt-AS_CVE-2024-48197.md) 🟡 ✅

**名称:** CVE-2024-48197-Audiocodes-XSS  
**类型:** 跨站脚本 (XSS)  
**风险:** 中危，可能导致权限提升和信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-05-06  
**POC仓库:** [CVE-2024-48197](https://github.com/GCatt-AS/CVE-2024-48197)  

---

### [CVE-2025-46731](CVE-2025-46731-singetu0096_CVE-2025-46731.md) 🔴 

**名称:** CVE-2025-46731 - Craft CMS Twig SSTI RCE  
**类型:** Twig SSTI (服务器端模板注入)  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-05-06  
**POC仓库:** [CVE-2025-46731](https://github.com/singetu0096/CVE-2025-46731)  

---

### [CVE-2025-3604](CVE-2025-3604-Nxploited_CVE-2025-3604.md) 🔴 ✅

**名称:** CVE-2025-3604-Flynax Bridge-权限提升  
**类型:** 权限提升  
**风险:** 高危，可导致账户接管  
**投毒风险:** 1%  
**发现时间:** 2025-05-06  
**POC仓库:** [CVE-2025-3604](https://github.com/Nxploited/CVE-2025-3604)  

---

### [CVE-2025-24801](CVE-2025-24801-fatkz_CVE-2025-24801.md) 🔴 ✅

**名称:** CVE-2025-24801-GLPI-RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-05-06  
**POC仓库:** [CVE-2025-24801](https://github.com/fatkz/CVE-2025-24801)  

---

### [CVE-2014-6271](CVE-2014-6271-Dilith006_CVE-2014-6271.md) 🔴 ✅

**名称:** CVE-2014-6271-Bash-Shellshock  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行和系统控制  
**投毒风险:** 10%  
**发现时间:** 2025-05-05  
**POC仓库:** [CVE-2014-6271](https://github.com/Dilith006/CVE-2014-6271)  

---

### [CVE-2014-6271](CVE-2014-6271-indiandragon_Shellshock-Vulnerability-Scan.md) 🔴 ✅

**名称:** CVE-2014-6271 ShellShock  
**类型:** 远程代码执行  
**风险:** 高危，允许远程攻击者执行任意代码  
**投毒风险:** 1%  
**发现时间:** 2025-05-05  
**POC仓库:** [Shellshock-Vulnerability-Scan](https://github.com/indiandragon/Shellshock-Vulnerability-Scan)  

---

### [CVE-2014-6271](CVE-2014-6271-MuirlandOracle_CVE-2014-6271-IPFire.md) 🔴 ✅

**名称:** CVE-2014-6271 IP Fire Shellshock RCE  
**类型:** 远程代码执行  
**风险:** 高危，允许未经授权的远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-05-05  
**POC仓库:** [CVE-2014-6271-IPFire](https://github.com/MuirlandOracle/CVE-2014-6271-IPFire)  

---

### [CVE-2014-6271](CVE-2014-6271-moften_CVE-2014-6271.md) 🔴 ✅

**名称:** CVE-2014-6271 Shellshock漏洞扫描器  
**类型:** 远程代码执行  
**风险:** 高危，允许攻击者执行任意命令  
**投毒风险:** 10%  
**发现时间:** 2025-05-05  
**POC仓库:** [CVE-2014-6271](https://github.com/moften/CVE-2014-6271)  

---

### [CVE-2025-3248](CVE-2025-3248-Praison001_CVE-2025-3248.md) 🔴 ✅

**名称:** CVE-2025-3248 - Langflow Unauth RCE  
**类型:** 代码注入  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-05-05  
**POC仓库:** [CVE-2025-3248](https://github.com/Praison001/CVE-2025-3248)  

---

### [CVE-2025-29448](CVE-2025-29448-Abdullah4eb_CVE-2025-29448.md) 🔴 ✅

**名称:** CVE-2025-29448-Easy!Appointments-DoS  
**类型:** 拒绝服务 (DoS)  
**风险:** 高危，导致服务不可用  
**投毒风险:** 0%  
**发现时间:** 2025-05-05  
**POC仓库:** [CVE-2025-29448](https://github.com/Abdullah4eb/CVE-2025-29448)  

---

### [CVE-2025-3776](CVE-2025-3776-Totunm_CVE-2025-3776.md) 🔴 ✅

**名称:** CVE-2025-3776 - Verification SMS with TargetSMS <= 1.5 - Unauthenticated Limited Remote Code Execution  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，允许未经身份验证的攻击者执行任意PHP函数，可能导致敏感信息泄露，修改网站内容，甚至完全控制服务器。  
**投毒风险:** 10%  
**发现时间:** 2025-05-05  
**POC仓库:** [CVE-2025-3776](https://github.com/Totunm/CVE-2025-3776)  

---

### [CVE-2025-47256](CVE-2025-47256-SexyShoelessGodofWar_CVE-2025-47256.md) 🔴 ✅

**名称:** CVE-2025-47226  
**类型:** 栈缓冲区溢出  
**风险:** 高危，可能导致拒绝服务（DoS）或远程代码执行（RCE）  
**投毒风险:** 10%  
**发现时间:** 2025-05-05  
**POC仓库:** [CVE-2025-47256](https://github.com/SexyShoelessGodofWar/CVE-2025-47256)  

---

### [CVE-2025-28062](CVE-2025-28062-Thvt0ne_CVE-2025-28062.md) 🟡 ✅

**名称:** Frappe框架潜在的CSRF漏洞  
**类型:** 跨站请求伪造 (CSRF)  
**风险:** 中危，可能导致未授权的用户数据修改或删除  
**投毒风险:** 10%  
**发现时间:** 2025-05-05  
**POC仓库:** [CVE-2025-28062](https://github.com/Thvt0ne/CVE-2025-28062)  

---

### [CVE-2020-13405](CVE-2020-13405-mrnazu_CVE-2020-13405.md) 🟡 ✅

**名称:** CVE-2020-13405-Microweber-用户数据库泄露  
**类型:** 信息泄露  
**风险:** 中危，可能导致用户凭据泄露  
**投毒风险:** 1%  
**发现时间:** 2025-05-05  
**POC仓库:** [CVE-2020-13405](https://github.com/mrnazu/CVE-2020-13405)  

---

### [CVE-2020-13405](CVE-2020-13405-Moniruzzaman995_CVE-2020-13405.md) 🟡 ✅

**名称:** CVE-2020-13405-Microweber-用户信息泄露  
**类型:** 信息泄露  
**风险:** 中危，泄露用户信息  
**投毒风险:** 0%  
**发现时间:** 2025-05-05  
**POC仓库:** [CVE-2020-13405](https://github.com/Moniruzzaman995/CVE-2020-13405)  

---

### [CVE-2025-3969](CVE-2025-3969-Stuub_CVE-2025-3969-Exploit.md) 🔴 ✅

**名称:** CVE-2025-3969-News Publishing Site Dashboard-Unrestricted Upload  
**类型:** Unrestricted Upload  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-05-05  
**POC仓库:** [CVE-2025-3969-Exploit](https://github.com/Stuub/CVE-2025-3969-Exploit)  

---

### [CVE-2024-21546](CVE-2024-21546-ajdumanhug_CVE-2024-21546.md)  ✅

**名称:** CVE-2024-21546-laravel-filemanager-RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 严重，可能导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-05-05  
**POC仓库:** [CVE-2024-21546](https://github.com/ajdumanhug/CVE-2024-21546)  

---

### [CVE-2025-24893](CVE-2025-24893-Wormwdcold_CVE-2025-24893-EXP.md) 🔴 ✅

**名称:** CVE-2025-24893-XWiki-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-05-05  
**POC仓库:** [CVE-2025-24893-EXP](https://github.com/Wormwdcold/CVE-2025-24893-EXP)  

---

### [CVE-2023-22518](CVE-2023-22518-RevoltSecurities_CVE-2023-22518.md) 🔴 ✅

**名称:** CVE-2023-22518 - Atlassian Confluence Improper Authorization  
**类型:** Improper Authorization  
**风险:** 高危，可能导致完全的机密性、完整性和可用性丧失  
**投毒风险:** 10%  
**发现时间:** 2025-05-05  
**POC仓库:** [CVE-2023-22518](https://github.com/RevoltSecurities/CVE-2023-22518)  

---

### [CVE-2023-22518](CVE-2023-22518-0x0d3ad_CVE-2023-22518.md)  ✅

**名称:** CVE-2023-22518-Confluence-不当授权  
**类型:** 不当授权  
**风险:** 严重，可能导致完全机密性、完整性和可用性损失  
**投毒风险:** 10%  
**发现时间:** 2025-05-05  
**POC仓库:** [CVE-2023-22518](https://github.com/0x0d3ad/CVE-2023-22518)  

---

### [CVE-2023-22518](CVE-2023-22518-ForceFledgling_CVE-2023-22518.md) 🔴 ✅

**名称:** CVE-2023-22518 - Atlassian Confluence Improper Authorization  
**类型:** Improper Authorization  
**风险:** 高危，可能导致完全机密性、完整性和可用性损失  
**投毒风险:** 0%  
**发现时间:** 2025-05-05  
**POC仓库:** [CVE-2023-22518](https://github.com/ForceFledgling/CVE-2023-22518)  

---

### [CVE-2023-22518](CVE-2023-22518-C1ph3rX13_CVE-2023-22518.md) 🔴 ✅

**名称:** CVE-2023-22518-Atlassian Confluence 认证绕过  
**类型:** 认证绕过  
**风险:** 高危，可能导致完全控制 Confluence 实例  
**投毒风险:** 10%  
**发现时间:** 2025-05-05  
**POC仓库:** [CVE-2023-22518](https://github.com/C1ph3rX13/CVE-2023-22518)  

---

### [CVE-2023-22518](CVE-2023-22518-bibo318_CVE-2023-22518.md) 🔴 ✅

**名称:** CVE-2023-22518-Atlassian Confluence-未授权重置与管理员创建  
**类型:** 未授权访问  
**风险:** 高危，完全丧失机密性、完整性和可用性  
**投毒风险:** 10%  
**发现时间:** 2025-05-05  
**POC仓库:** [CVE-2023-22518](https://github.com/bibo318/CVE-2023-22518)  

---

### [CVE-2023-22518](CVE-2023-22518-Lilly-dox_Exploit-CVE-2023-22518.md)  ✅

**名称:** CVE-2023-22518-Confluence-不当授权漏洞  
**类型:** 不当授权  
**风险:** 严重，可能导致完全丧失机密性、完整性和可用性  
**投毒风险:** 30%  
**发现时间:** 2025-05-05  
**POC仓库:** [Exploit-CVE-2023-22518](https://github.com/Lilly-dox/Exploit-CVE-2023-22518)  

---

### [CVE-2023-22518](CVE-2023-22518-davidfortytwo_CVE-2023-22518.md) 🔴 ✅

**名称:** CVE-2023-22518 - Confluence Server/Data Center Improper Authorization  
**类型:** Improper Authorization  
**风险:** 高危，完全丧失保密性、完整性和可用性  
**投毒风险:** 5%  
**发现时间:** 2025-05-05  
**POC仓库:** [CVE-2023-22518](https://github.com/davidfortytwo/CVE-2023-22518)  

---

### [CVE-2023-22518](CVE-2023-22518-ductink98lhp_analyze-Exploit-CVE-2023-22518-Confluence.md) 🔴 ✅

**名称:** CVE-2023-22518 - Atlassian Confluence Improper Authorization  
**类型:** Improper Authorization  
**风险:** Critical，完全控制 Confluence 实例，导致机密性、完整性和可用性完全丧失。  
**投毒风险:** 10%  
**发现时间:** 2025-05-05  
**POC仓库:** [analyze-Exploit-CVE-2023-22518-Confluence](https://github.com/ductink98lhp/analyze-Exploit-CVE-2023-22518-Confluence)  

---

### [CVE-2024-49138](CVE-2024-49138-Glitch-ao_SOC335-CVE-2024-49138-Exploitation-Detected.md) 🔴 ✅

**名称:** CVE-2024-49138 Windows CLFS 特权提升漏洞  
**类型:** 特权提升  
**风险:** 高危，可导致本地权限提升  
**投毒风险:** 10%  
**发现时间:** 2025-05-04  
**POC仓库:** [SOC335-CVE-2024-49138-Exploitation-Detected](https://github.com/Glitch-ao/SOC335-CVE-2024-49138-Exploitation-Detected)  

---

### [CVE-2023-46604](CVE-2023-46604-ImuSpirit_ActiveMQ_RCE_Pro_Max.md) 🔴 ✅

**名称:** CVE-2023-46604-Apache ActiveMQ-远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-05-04  
**POC仓库:** [ActiveMQ_RCE_Pro_Max](https://github.com/ImuSpirit/ActiveMQ_RCE_Pro_Max)  

---

### [CVE-2023-46604](CVE-2023-46604-SaumyajeetDas_CVE-2023-46604-RCE-Reverse-Shell-Apache-ActiveMQ.md) 🔴 ✅

**名称:** CVE-2023-46604-Apache ActiveMQ-远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致远程代码执行和服务器控制  
**投毒风险:** 5%  
**发现时间:** 2025-05-04  
**POC仓库:** [CVE-2023-46604-RCE-Reverse-Shell-Apache-ActiveMQ](https://github.com/SaumyajeetDas/CVE-2023-46604-RCE-Reverse-Shell-Apache-ActiveMQ)  

---

### [CVE-2023-46604](CVE-2023-46604-trganda_ActiveMQ-RCE.md) 🔴 ✅

**名称:** CVE-2023-46604 - Apache ActiveMQ RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可导致服务器被完全控制  
**投毒风险:** 5%  
**发现时间:** 2025-05-04  
**POC仓库:** [ActiveMQ-RCE](https://github.com/trganda/ActiveMQ-RCE)  

---

### [CVE-2023-46604](CVE-2023-46604-evkl1d_CVE-2023-46604.md) 🔴 ✅

**名称:** CVE-2023-46604-Apache ActiveMQ-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行和系统控制  
**投毒风险:** 5%  
**发现时间:** 2025-05-04  
**POC仓库:** [CVE-2023-46604](https://github.com/evkl1d/CVE-2023-46604)  

---

### [CVE-2023-46604](CVE-2023-46604-justdoit-cai_CVE-2023-46604-Apache-ActiveMQ-RCE-exp.md) 🔴 ✅

**名称:** CVE-2023-46604-Apache ActiveMQ-远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-05-04  
**POC仓库:** [CVE-2023-46604-Apache-ActiveMQ-RCE-exp](https://github.com/justdoit-cai/CVE-2023-46604-Apache-ActiveMQ-RCE-exp)  

---

### [CVE-2023-46604](CVE-2023-46604-LiritoShawshark_CVE-2023-46604_ActiveMQ_RCE_Recurrence.md) 🔴 ✅

**名称:** CVE-2023-46604-Apache ActiveMQ-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，允许未经身份验证的远程攻击者执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-05-04  
**POC仓库:** [CVE-2023-46604_ActiveMQ_RCE_Recurrence](https://github.com/LiritoShawshark/CVE-2023-46604_ActiveMQ_RCE_Recurrence)  

---

### [CVE-2023-46604](CVE-2023-46604-vjayant93_CVE-2023-46604-POC.md) 🔴 ✅

**名称:** CVE-2023-46604-Apache ActiveMQ RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-05-04  
**POC仓库:** [CVE-2023-46604-POC](https://github.com/vjayant93/CVE-2023-46604-POC)  

---

### [CVE-2023-46604](CVE-2023-46604-NKeshawarz_CVE-2023-46604-RCE.md) 🔴 ✅

**名称:** CVE-2023-46604 Apache ActiveMQ RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致完全控制受影响系统  
**投毒风险:** 10%  
**发现时间:** 2025-05-04  
**POC仓库:** [CVE-2023-46604-RCE](https://github.com/NKeshawarz/CVE-2023-46604-RCE)  

---

### [CVE-2023-46604](CVE-2023-46604-minhangxiaohui_ActiveMQ_CVE-2023-46604.md) 🔴 ✅

**名称:** CVE-2023-46604-Apache ActiveMQ-RCE  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行，系统完全控制  
**投毒风险:** 1%  
**发现时间:** 2025-05-04  
**POC仓库:** [ActiveMQ_CVE-2023-46604](https://github.com/minhangxiaohui/ActiveMQ_CVE-2023-46604)  

---

### [CVE-2023-46604](CVE-2023-46604-dcm2406_CVE-2023-46604.md) 🔴 ✅

**名称:** CVE-2023-46604-Apache ActiveMQ-RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-05-04  
**POC仓库:** [CVE-2023-46604](https://github.com/dcm2406/CVE-2023-46604)  

---

### [CVE-2023-46604](CVE-2023-46604-Mudoleto_Broker_ApacheMQ.md) 🔴 ✅

**名称:** CVE-2023-46604-Apache ActiveMQ-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行和系统被控制  
**投毒风险:** 0%  
**发现时间:** 2025-05-04  
**POC仓库:** [Broker_ApacheMQ](https://github.com/Mudoleto/Broker_ApacheMQ)  

---

### [CVE-2023-46604](CVE-2023-46604-duck-sec_CVE-2023-46604-ActiveMQ-RCE-pseudoshell.md)  ✅

**名称:** CVE-2023-46604 - Apache ActiveMQ - 远程代码执行  
**类型:** 反序列化漏洞导致远程代码执行  
**风险:** 严重，可导致远程代码执行，完全控制受影响的系统  
**投毒风险:** 0%  
**发现时间:** 2025-05-04  
**POC仓库:** [CVE-2023-46604-ActiveMQ-RCE-pseudoshell](https://github.com/duck-sec/CVE-2023-46604-ActiveMQ-RCE-pseudoshell)  

---

### [CVE-2023-46604](CVE-2023-46604-X1r0z_ActiveMQ-RCE.md)  ✅

**名称:** CVE-2023-46604 - Apache ActiveMQ RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 严重，可能导致完全系统控制  
**投毒风险:** 0%  
**发现时间:** 2025-05-04  
**POC仓库:** [ActiveMQ-RCE](https://github.com/X1r0z/ActiveMQ-RCE)  

---

### [CVE-2023-46604](CVE-2023-46604-stegano5_ExploitScript-CVE-2023-46604.md) 🔴 ✅

**名称:** CVE-2023-46604-Apache ActiveMQ-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可导致服务器被完全控制  
**投毒风险:** 5%  
**发现时间:** 2025-05-04  
**POC仓库:** [ExploitScript-CVE-2023-46604](https://github.com/stegano5/ExploitScript-CVE-2023-46604)  

---

### [CVE-2023-46604](CVE-2023-46604-mrpentst_CVE-2023-46604.md) 🔴 ✅

**名称:** CVE-2023-46604-Apache ActiveMQ-远程代码执行  
**类型:** 反序列化漏洞  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-05-04  
**POC仓库:** [CVE-2023-46604](https://github.com/mrpentst/CVE-2023-46604)  

---

### [CVE-2023-46604](CVE-2023-46604-thinkycx_activemq-rce-cve-2023-46604.md) 🔴 ✅

**名称:** CVE-2023-46604 - Apache ActiveMQ OpenWire RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-05-04  
**POC仓库:** [activemq-rce-cve-2023-46604](https://github.com/thinkycx/activemq-rce-cve-2023-46604)  

---

### [CVE-2023-46604](CVE-2023-46604-mranv_honeypot.rs.md) 🔴 ✅

**名称:** CVE-2023-46604-Apache ActiveMQ-RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 1%  
**发现时间:** 2025-05-04  
**POC仓库:** [honeypot.rs](https://github.com/mranv/honeypot.rs)  

---

### [CVE-2023-46604](CVE-2023-46604-pulentoski_CVE-2023-46604.md) 🔴 ✅

**名称:** CVE-2023-46604 - Apache ActiveMQ OpenWire 反序列化 RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致完全控制受影响的系统  
**投毒风险:** 0%  
**发现时间:** 2025-05-04  
**POC仓库:** [CVE-2023-46604](https://github.com/pulentoski/CVE-2023-46604)  

---

### [CVE-2023-46604](CVE-2023-46604-Arlenhiack_ActiveMQ-RCE-Exploit.md) 🔴 ✅

**名称:** CVE-2023-46604 Apache ActiveMQ RCE  
**类型:** 远程代码执行  
**风险:** 高危，可导致完全控制服务器  
**投毒风险:** 10%  
**发现时间:** 2025-05-04  
**POC仓库:** [ActiveMQ-RCE-Exploit](https://github.com/Arlenhiack/ActiveMQ-RCE-Exploit)  

---

### [CVE-2023-46604](CVE-2023-46604-vulncheck-oss_cve-2023-46604.md) 🔴 ✅

**名称:** CVE-2023-46604-Apache ActiveMQ-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行和系统控制  
**投毒风险:** 0%  
**发现时间:** 2025-05-04  
**POC仓库:** [cve-2023-46604](https://github.com/vulncheck-oss/cve-2023-46604)  

---

### [CVE-2023-46604](CVE-2023-46604-nitzanoligo_CVE-2023-46604-demo.md) 🔴 ✅

**名称:** CVE-2023-46604-Apache ActiveMQ-RCE  
**类型:** 远程代码执行  
**风险:** 高危，可导致服务器完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-05-04  
**POC仓库:** [CVE-2023-46604-demo](https://github.com/nitzanoligo/CVE-2023-46604-demo)  

---

### [CVE-2023-46604](CVE-2023-46604-cuanh2333_CVE-2023-46604.md) 🔴 ✅

**名称:** CVE-2023-46604-Apache ActiveMQ-RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，允许远程攻击者执行任意shell命令  
**投毒风险:** 10%  
**发现时间:** 2025-05-04  
**POC仓库:** [CVE-2023-46604](https://github.com/cuanh2333/CVE-2023-46604)  

---

### [CVE-2023-46604](CVE-2023-46604-tomasmussi_activemq-cve-2023-46604.md) 🔴 ✅

**名称:** CVE-2023-46604-Apache ActiveMQ-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致完全控制 ActiveMQ Broker 或 Client  
**投毒风险:** 10%  
**发现时间:** 2025-05-04  
**POC仓库:** [activemq-cve-2023-46604](https://github.com/tomasmussi/activemq-cve-2023-46604)  

---

### [CVE-2023-46604](CVE-2023-46604-skrkcb2_CVE-2023-46604.md) 🔴 ✅

**名称:** CVE-2023-46604-Apache ActiveMQ-远程代码执行  
**类型:** 远程代码执行(RCE)  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 5%  
**发现时间:** 2025-05-04  
**POC仓库:** [CVE-2023-46604](https://github.com/skrkcb2/CVE-2023-46604)  

---

### [CVE-2023-46604](CVE-2023-46604-CCIEVoice2009_CVE-2023-46604.md) 🔴 ✅

**名称:** CVE-2023-46604-Apache ActiveMQ-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，允许未经身份验证的远程攻击者执行任意代码  
**投毒风险:** 1%  
**发现时间:** 2025-05-04  
**POC仓库:** [CVE-2023-46604](https://github.com/CCIEVoice2009/CVE-2023-46604)  

---

### [CVE-2021-1931](CVE-2021-1931-FakeShell_CVE-2021-1931-BBRY-KEY2.md) 🔴 ✅

**名称:** CVE-2021-1931-Qualcomm-fastboot-buffer-overflow  
**类型:** 缓冲区溢出  
**风险:** 高危，可能导致代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-05-04  
**POC仓库:** [CVE-2021-1931-BBRY-KEY2](https://github.com/FakeShell/CVE-2021-1931-BBRY-KEY2)  

---

### [CVE-2024-36401](CVE-2024-36401-cochaviz_cve-2024-36401-poc.md) 🔴 ✅

**名称:** CVE-2024-36401-GeoServer-RCE  
**类型:** 远程代码执行(RCE)  
**风险:** 高危，未经身份验证的远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-05-04  
**POC仓库:** [cve-2024-36401-poc](https://github.com/cochaviz/cve-2024-36401-poc)  

---

### [CVE-2024-52302](CVE-2024-52302-d3sca_CVE-2024-52302.md) 🔴 ✅

**名称:** CVE-2024-52302-common-user-management-任意文件上传导致RCE  
**类型:** 任意文件上传  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-05-04  
**POC仓库:** [CVE-2024-52302](https://github.com/d3sca/CVE-2024-52302)  

---

### [CVE-2025-1323](CVE-2025-1323-p33d_cve-2025-1323.md) 🔴 ✅

**名称:** CVE-2025-1323-WP-Recall-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-05-03  
**POC仓库:** [cve-2025-1323](https://github.com/p33d/cve-2025-1323)  

---

### [CVE-2025-47240](CVE-2025-47240-Oblivionsage_fastify-cve-2025-47240.md) 🟡 ✅

**名称:** CVE-2024-47240 - Dell Secure Connect Gateway 本地权限提升  
**类型:** 权限提升  
**风险:** 中危，可能导致本地权限提升  
**投毒风险:** 0%  
**发现时间:** 2025-05-03  
**POC仓库:** [fastify-cve-2025-47240](https://github.com/Oblivionsage/fastify-cve-2025-47240)  

---

### [CVE-2025-26529](CVE-2025-26529-exfil0_UNISA_CVE-2025-26529.md) 🔴 ✅

**名称:** CVE-2025-26529-Moodle-Stored XSS  
**类型:** Stored XSS  
**风险:** 高危，可能导致账户劫持、权限提升、恶意代码执行。  
**投毒风险:** 10%  
**发现时间:** 2025-05-03  
**POC仓库:** [UNISA_CVE-2025-26529](https://github.com/exfil0/UNISA_CVE-2025-26529)  

---

### [CVE-2025-32375](CVE-2025-32375-theGEBIRGE_CVE-2025-32375.md)  ✅

**名称:** CVE-2025-32375-BentoML-RCE  
**类型:** 反序列化漏洞导致远程代码执行  
**风险:** 严重，可能导致完全控制受影响的服务器  
**投毒风险:** 0%  
**发现时间:** 2025-05-03  
**POC仓库:** [CVE-2025-32375](https://github.com/theGEBIRGE/CVE-2025-32375)  

---

### [CVE-2025-47226](CVE-2025-47226-koyomihack00_CVE-2025-47226.md) 🟡 ✅

**名称:** CVE-2025-47226 - Snipe-IT 资产信息未授权访问漏洞  
**类型:** 未授权访问 / IDOR (Insecure Direct Object Reference)  
**风险:** 中危，可能导致敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-05-03  
**POC仓库:** [CVE-2025-47226](https://github.com/koyomihack00/CVE-2025-47226)  

---

### [CVE-2025-32433](CVE-2025-32433-vigilante-1337_CVE-2025-32433.md)  ✅

**名称:** CVE-2025-32433-Erlang/OTP SSH RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 严重，无需身份验证即可远程执行代码  
**投毒风险:** 10%  
**发现时间:** 2025-05-03  
**POC仓库:** [CVE-2025-32433](https://github.com/vigilante-1337/CVE-2025-32433)  

---

### [CVE-2025-29927](CVE-2025-29927-olimpiofreitas_CVE-2025-29927_scanner.md) 🔴 ✅

**名称:** CVE-2025-29927-Next.js中间件授权绕过  
**类型:** 授权绕过  
**风险:** 高危，可能导致未经授权的访问和数据泄露  
**投毒风险:** 5%  
**发现时间:** 2025-05-03  
**POC仓库:** [CVE-2025-29927_scanner](https://github.com/olimpiofreitas/CVE-2025-29927_scanner)  

---

### [CVE-2020-13151](CVE-2020-13151-b4ny4n_CVE-2020-13151.md) 🔴 ✅

**名称:** CVE-2020-13151 - Aerospike UDF远程命令执行  
**类型:** 远程命令执行  
**风险:** 高危，允许未经身份验证的远程命令执行  
**投毒风险:** 10%  
**发现时间:** 2025-05-03  
**POC仓库:** [CVE-2020-13151](https://github.com/b4ny4n/CVE-2020-13151)  

---

### [CVE-2020-13151](CVE-2020-13151-ByteMe1001_CVE-2020-13151-POC-Aerospike-Server-Host-Command-Execution-RCE-.md) 🔴 ✅

**名称:** CVE-2020-13151-Aerospike-RCE  
**类型:** 远程代码执行  
**风险:** 高危，可导致服务器被完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-05-03  
**POC仓库:** [CVE-2020-13151-POC-Aerospike-Server-Host-Command-Execution-RCE-](https://github.com/ByteMe1001/CVE-2020-13151-POC-Aerospike-Server-Host-Command-Execution-RCE-)  

---

### [CVE-2024-44308](CVE-2024-44308-migopp_cve-2024-44308.md) 🔴 ✅

**名称:** CVE-2024-44308-JavaScriptCore-RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可导致任意代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-05-03  
**POC仓库:** [cve-2024-44308](https://github.com/migopp/cve-2024-44308)  

---

### [CVE-2022-44268](CVE-2022-44268-katseyres2_CVE-2022-44268-pilgrimage.md) 🔴 ✅

**名称:** CVE-2022-44268-ImageMagick-任意文件读取  
**类型:** 任意文件读取  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 1%  
**发现时间:** 2025-05-02  
**POC仓库:** [CVE-2022-44268-pilgrimage](https://github.com/katseyres2/CVE-2022-44268-pilgrimage)  

---

### [CVE-2025-12654](CVE-2025-12654-Subha-coder-hash_Anydesk-Exploit-CVE-2025-12654-RCE-Builder.md) 🔴 ✅

**名称:** CVE-2025-12654-AnyDesk-RCE  
**类型:** 远程代码执行  
**风险:** 高危，允许攻击者在受影响系统上执行任意代码  
**投毒风险:** 5%  
**发现时间:** 2025-05-02  
**POC仓库:** [Anydesk-Exploit-CVE-2025-12654-RCE-Builder](https://github.com/Subha-coder-hash/Anydesk-Exploit-CVE-2025-12654-RCE-Builder)  

---

### [CVE-2025-3928](CVE-2025-3928-Totunm_CVE-2025-3928.md) 🔴 ✅

**名称:** CVE-2025-3928-Commvault Web Server-Webshell上传RCE  
**类型:** 远程代码执行  
**风险:** 高危，可能导致系统完全控制、数据泄露、横向渗透  
**投毒风险:** 85%  
**发现时间:** 2025-05-02  
**POC仓库:** [CVE-2025-3928](https://github.com/Totunm/CVE-2025-3928)  

---

### [CVE-2015-4133](CVE-2015-4133-sug4r-wr41th_CVE-2015-4133.md) 🔴 ✅

**名称:** CVE-2015-4133-ReFlex Gallery-任意文件上传  
**类型:** 任意文件上传  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-05-02  
**POC仓库:** [CVE-2015-4133](https://github.com/sug4r-wr41th/CVE-2015-4133)  

---

### [CVE-2025-31324](CVE-2025-31324-Onapsis_Onapsis-Mandiant-CVE-2025-31324-Vuln-Compromise-Assessment.md) 🔴 ✅

**名称:** CVE-2025-31324-SAP NetWeaver Visual Composer-未授权文件上传  
**类型:** 未授权文件上传  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-05-02  
**POC仓库:** [Onapsis-Mandiant-CVE-2025-31324-Vuln-Compromise-Assessment](https://github.com/Onapsis/Onapsis-Mandiant-CVE-2025-31324-Vuln-Compromise-Assessment)  

---

### [CVE-2025-1304](CVE-2025-1304-Nxploited_CVE-2025-1304.md) 🔴 ✅

**名称:** CVE-2025-1304-NewsBlogger-Arbitrary File Upload  
**类型:** Arbitrary File Upload  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-05-02  
**POC仓库:** [CVE-2025-1304](https://github.com/Nxploited/CVE-2025-1304)  

---

### [CVE-2016-5195](CVE-2016-5195-scumjr_dirtycow-vdso.md) 🔴 ✅

**名称:** CVE-2016-5195 Dirty COW  
**类型:** 权限提升  
**风险:** 高危，本地用户可获得root权限  
**投毒风险:** 10%  
**发现时间:** 2025-05-02  
**POC仓库:** [dirtycow-vdso](https://github.com/scumjr/dirtycow-vdso)  

---

### [CVE-2016-5195](CVE-2016-5195-dulanjaya23_Dirty-Cow-CVE-2016-5195-.md) 🔴 ✅

**名称:** CVE-2016-5195-Dirty COW-权限提升漏洞  
**类型:** 权限提升  
**风险:** 高危，可导致本地用户获取 root 权限  
**投毒风险:** 10%  
**发现时间:** 2025-05-02  
**POC仓库:** [Dirty-Cow-CVE-2016-5195-](https://github.com/dulanjaya23/Dirty-Cow-CVE-2016-5195-)  

---

### [CVE-2016-5195](CVE-2016-5195-zakariamaaraki_Dirty-COW-CVE-2016-5195-.md) 🔴 ✅

**名称:** CVE-2016-5195 - Dirty COW  
**类型:** 权限提升  
**风险:** 高危，本地用户可以提升权限至root  
**投毒风险:** 10%  
**发现时间:** 2025-05-02  
**POC仓库:** [Dirty-COW-CVE-2016-5195-](https://github.com/zakariamaaraki/Dirty-COW-CVE-2016-5195-)  

---

### [CVE-2016-5195](CVE-2016-5195-timwr_CVE-2016-5195.md) 🔴 ✅

**名称:** CVE-2016-5195 - Dirty COW  
**类型:** 权限提升  
**风险:** 高危，本地用户可获取root权限  
**投毒风险:** 10%  
**发现时间:** 2025-05-02  
**POC仓库:** [CVE-2016-5195](https://github.com/timwr/CVE-2016-5195)  

---

### [CVE-2016-5195](CVE-2016-5195-DanielEbert_CVE-2016-5195.md) 🔴 ✅

**名称:** CVE-2016-5195 - Dirty COW 本地提权漏洞  
**类型:** 本地提权  
**风险:** 高危，可导致本地用户获取 root 权限  
**投毒风险:** 10%  
**发现时间:** 2025-05-02  
**POC仓库:** [CVE-2016-5195](https://github.com/DanielEbert/CVE-2016-5195)  

---

### [CVE-2016-5195](CVE-2016-5195-firefart_dirtycow.md) 🔴 ✅

**名称:** CVE-2016-5195 - Dirty COW 本地提权  
**类型:** 本地权限提升  
**风险:** 高危，可导致普通用户提升为 root 权限  
**投毒风险:** 10%  
**发现时间:** 2025-05-02  
**POC仓库:** [dirtycow](https://github.com/firefart/dirtycow)  

---

### [CVE-2016-5195](CVE-2016-5195-KasunPriyashan_Y2S1-Project-Linux-Exploitaion-using-CVE-2016-5195-Vulnerability.md) 🔴 ✅

**名称:** CVE-2016-5195 - Dirty COW  
**类型:** 权限提升  
**风险:** 高危，允许本地用户提升权限  
**投毒风险:** 10%  
**发现时间:** 2025-05-02  
**POC仓库:** [Y2S1-Project-Linux-Exploitaion-using-CVE-2016-5195-Vulnerability](https://github.com/KasunPriyashan/Y2S1-Project-Linux-Exploitaion-using-CVE-2016-5195-Vulnerability)  

---

### [CVE-2016-5195](CVE-2016-5195-th3-5had0w_DirtyCOW-PoC.md) 🔴 ✅

**名称:** CVE-2016-5195 Dirty COW  
**类型:** 权限提升  
**风险:** 高危，可导致本地用户获取root权限  
**投毒风险:** 0%  
**发现时间:** 2025-05-02  
**POC仓库:** [DirtyCOW-PoC](https://github.com/th3-5had0w/DirtyCOW-PoC)  

---

### [CVE-2016-5195](CVE-2016-5195-TotallyNotAHaxxer_CVE-2016-5195.md) 🔴 ✅

**名称:** CVE-2016-5195 - Dirty COW 本地提权漏洞  
**类型:** 本地提权  
**风险:** 高危，可导致普通用户提升至root权限  
**投毒风险:** 5%  
**发现时间:** 2025-05-02  
**POC仓库:** [CVE-2016-5195](https://github.com/TotallyNotAHaxxer/CVE-2016-5195)  

---

### [CVE-2016-5195](CVE-2016-5195-passionchenjianyegmail8_scumjrs.md) 🔴 ✅

**名称:** CVE-2016-5195 Dirty COW  
**类型:** 权限提升  
**风险:** 高危，本地用户可获取root权限  
**投毒风险:** 10%  
**发现时间:** 2025-05-02  
**POC仓库:** [scumjrs](https://github.com/passionchenjianyegmail8/scumjrs)  

---

### [CVE-2016-5195](CVE-2016-5195-gurpreetsinghsaluja_dirtycow.md) 🔴 ✅

**名称:** CVE-2016-5195 - Dirty COW  
**类型:** 权限提升  
**风险:** 高危，可导致本地用户获取 root 权限  
**投毒风险:** 10%  
**发现时间:** 2025-05-02  
**POC仓库:** [dirtycow](https://github.com/gurpreetsinghsaluja/dirtycow)  

---

### [CVE-2016-5195](CVE-2016-5195-KaviDk_dirtyCow.md) 🔴 ✅

**名称:** CVE-2016-5195 - Dirty COW  
**类型:** 权限提升  
**风险:** 高危，允许本地用户获取 root 权限  
**投毒风险:** 10%  
**发现时间:** 2025-05-02  
**POC仓库:** [dirtyCow](https://github.com/KaviDk/dirtyCow)  

---

### [CVE-2016-5195](CVE-2016-5195-fei9747_CVE-2016-5195.md) 🔴 ✅

**名称:** CVE-2016-5195 - Dirty COW 本地提权  
**类型:** 本地权限提升  
**风险:** 高危，可导致普通用户获得root权限  
**投毒风险:** 1%  
**发现时间:** 2025-05-02  
**POC仓库:** [CVE-2016-5195](https://github.com/fei9747/CVE-2016-5195)  

---

### [CVE-2016-5195](CVE-2016-5195-LinuxKernelContent_DirtyCow.md) 🔴 ✅

**名称:** CVE-2016-5195 - Dirty COW  
**类型:** 权限提升  
**风险:** 高危，可使普通用户获得root权限  
**投毒风险:** 0%  
**发现时间:** 2025-05-02  
**POC仓库:** [DirtyCow](https://github.com/LinuxKernelContent/DirtyCow)  

---

### [CVE-2016-5195](CVE-2016-5195-h1n4mx0_Research-CVE-2016-5195.md) 🔴 ✅

**名称:** CVE-2016-5195 Dirty COW 本地提权漏洞  
**类型:** 权限提升  
**风险:** 高危，可从低权限用户提升到root权限  
**投毒风险:** 10%  
**发现时间:** 2025-05-02  
**POC仓库:** [Research-CVE-2016-5195](https://github.com/h1n4mx0/Research-CVE-2016-5195)  

---

### [CVE-2016-5195](CVE-2016-5195-EDLLT_CVE-2016-5195-master.md) 🔴 ✅

**名称:** CVE-2016-5195 Dirty COW  
**类型:** 权限提升  
**风险:** 高危，可导致本地用户获取 root 权限  
**投毒风险:** 10%  
**发现时间:** 2025-05-02  
**POC仓库:** [CVE-2016-5195-master](https://github.com/EDLLT/CVE-2016-5195-master)  

---

### [CVE-2016-5195](CVE-2016-5195-ZhiQiAnSecFork_DirtyCOW_CVE-2016-5195.md) 🔴 ✅

**名称:** CVE-2016-5195 Dirty COW  
**类型:** 权限提升  
**风险:** 高危，本地用户可获得root权限  
**投毒风险:** 10%  
**发现时间:** 2025-05-02  
**POC仓库:** [DirtyCOW_CVE-2016-5195](https://github.com/ZhiQiAnSecFork/DirtyCOW_CVE-2016-5195)  

---

### [CVE-2016-5195](CVE-2016-5195-sakilahamed_Linux-Kernel-Exploit-LAB.md) 🔴 ✅

**名称:** CVE-2016-5195 Dirty COW  
**类型:** 本地提权  
**风险:** 高危，本地用户可提升为root权限  
**投毒风险:** 5%  
**发现时间:** 2025-05-02  
**POC仓库:** [Linux-Kernel-Exploit-LAB](https://github.com/sakilahamed/Linux-Kernel-Exploit-LAB)  

---

### [CVE-2016-5195](CVE-2016-5195-ASUKA39_CVE-2016-5195.md) 🔴 ✅

**名称:** CVE-2016-5195 Dirty COW  
**类型:** 权限提升  
**风险:** 高危，本地用户可获得 root 权限  
**投毒风险:** 5%  
**发现时间:** 2025-05-02  
**POC仓库:** [CVE-2016-5195](https://github.com/ASUKA39/CVE-2016-5195)  

---

### [CVE-2016-5195](CVE-2016-5195-arttnba3_CVE-2016-5195.md) 🔴 ✅

**名称:** CVE-2016-5195 Dirty COW  
**类型:** 权限提升  
**风险:** 高危，可使本地用户获得 root 权限  
**投毒风险:** 10%  
**发现时间:** 2025-05-02  
**POC仓库:** [CVE-2016-5195](https://github.com/arttnba3/CVE-2016-5195)  

---

### [CVE-2016-5195](CVE-2016-5195-talsim_root-dirtyc0w.md) 🔴 ✅

**名称:** CVE-2016-5195 - Dirty COW  
**类型:** 权限提升  
**风险:** 高危，本地用户可获取root权限  
**投毒风险:** 10%  
**发现时间:** 2025-05-02  
**POC仓库:** [root-dirtyc0w](https://github.com/talsim/root-dirtyc0w)  

---

### [CVE-2016-5195](CVE-2016-5195-LiEnby_PSSRoot.md) 🔴 ✅

**名称:** CVE-2016-5195 - Dirty COW  
**类型:** 权限提升  
**风险:** 高危，本地用户可获得 root 权限  
**投毒风险:** 10%  
**发现时间:** 2025-05-02  
**POC仓库:** [PSSRoot](https://github.com/LiEnby/PSSRoot)  

---

### [CVE-2016-5195](CVE-2016-5195-0x3n19m4_CVE-2016-5195.md) 🔴 ✅

**名称:** CVE-2016-5195 Dirty COW  
**类型:** 权限提升  
**风险:** 高危，可导致本地用户提升为root权限  
**投毒风险:** 0%  
**发现时间:** 2025-05-02  
**POC仓库:** [CVE-2016-5195](https://github.com/0x3n19m4/CVE-2016-5195)  

---

### [CVE-2023-46818](CVE-2023-46818-rvizx_CVE-2023-46818.md) 🔴 ✅

**名称:** CVE-2023-46818-ISPConfig-PHP代码注入  
**类型:** PHP代码注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-05-02  
**POC仓库:** [CVE-2023-46818](https://github.com/rvizx/CVE-2023-46818)  

---

### [CVE-2024-23113](CVE-2024-23113-CheckCve2_CVE-2024-23113.md) 🔴 ✅

**名称:** CVE-2024-23113-Fortinet-格式字符串漏洞  
**类型:** 格式字符串漏洞  
**风险:** 高危，允许攻击者执行未授权代码或命令  
**投毒风险:** 80%  
**发现时间:** 2025-05-02  
**POC仓库:** [CVE-2024-23113](https://github.com/CheckCve2/CVE-2024-23113)  

---

### [CVE-2024-23113](CVE-2024-23113-p33d_CVE-2024-23113.md) 🔴 ✅

**名称:** CVE-2024-23113 - Fortinet Format String Vulnerability  
**类型:** 格式化字符串漏洞  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-05-02  
**POC仓库:** [CVE-2024-23113](https://github.com/p33d/CVE-2024-23113)  

---

### [CVE-2024-23113](CVE-2024-23113-puckiestyle_CVE-2024-23113.md) 🔴 ✅

**名称:** CVE-2024-23113 - Fortinet Format String Vulnerability  
**类型:** Format String Vulnerability  
**风险:** 高危，远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-05-02  
**POC仓库:** [CVE-2024-23113](https://github.com/puckiestyle/CVE-2024-23113)  

---

### [CVE-2024-23113](CVE-2024-23113-expl0itsecurity_CVE-2024-23113.md) 🔴 ✅

**名称:** CVE-2024-23113 - Fortinet Format String RCE  
**类型:** 格式化字符串漏洞  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 60%  
**发现时间:** 2025-05-02  
**POC仓库:** [CVE-2024-23113](https://github.com/expl0itsecurity/CVE-2024-23113)  

---

### [CVE-2024-23113](CVE-2024-23113-XiaomingX_cve-2024-23113-exp.md) 🔴 ✅

**名称:** CVE-2024-23113-Fortinet-格式字符串漏洞  
**类型:** 格式字符串漏洞  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-05-02  
**POC仓库:** [cve-2024-23113-exp](https://github.com/XiaomingX/cve-2024-23113-exp)  

---

### [CVE-2024-23113](CVE-2024-23113-XiaomingX_cve-2024-23113-poc.md) 🔴 ✅

**名称:** CVE-2024-23113 - Fortinet Format String Vulnerability  
**类型:** 格式化字符串漏洞  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-05-02  
**POC仓库:** [cve-2024-23113-poc](https://github.com/XiaomingX/cve-2024-23113-poc)  

---

### [CVE-2024-23113](CVE-2024-23113-valornode_CVE-2024-23113.md) 🔴 ✅

**名称:** CVE-2024-23113 - Fortinet Format String Vulnerability  
**类型:** 格式化字符串漏洞  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-05-02  
**POC仓库:** [CVE-2024-23113](https://github.com/valornode/CVE-2024-23113)  

---

### [CVE-2025-31650](CVE-2025-31650-sattarbug_Analysis-of-TomcatKiller---CVE-2025-31650-Exploit-Tool.md) 🔴 ✅

**名称:** CVE-2025-31650-ApacheTomcat-DoS  
**类型:** DoS  
**风险:** 高危，可能导致服务拒绝  
**投毒风险:** 10%  
**发现时间:** 2025-05-02  
**POC仓库:** [Analysis-of-TomcatKiller---CVE-2025-31650-Exploit-Tool](https://github.com/sattarbug/Analysis-of-TomcatKiller---CVE-2025-31650-Exploit-Tool)  

---

### [CVE-2025-32433](CVE-2025-32433-bilalz5-github_Erlang-OTP-SSH-CVE-2025-32433.md) 🔴 ✅

**名称:** CVE-2025-32433-Erlang/OTP-SSH 远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，无需认证即可远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-05-02  
**POC仓库:** [Erlang-OTP-SSH-CVE-2025-32433](https://github.com/bilalz5-github/Erlang-OTP-SSH-CVE-2025-32433)  

---

### [CVE-2024-27956](CVE-2024-27956-devsec23_CVE-2024-27956.md) 🔴 ✅

**名称:** CVE-2024-27956 - WordPress Automatic Plugin SQL 注入  
**类型:** SQL 注入  
**风险:** 高危，未经身份验证的攻击者可以执行任意 SQL 查询，可能导致数据泄露、数据篡改，甚至完全控制 WordPress 站点。  
**投毒风险:** 10%  
**发现时间:** 2025-05-02  
**POC仓库:** [CVE-2024-27956](https://github.com/devsec23/CVE-2024-27956)  

---

### [CVE-2023-4226](CVE-2023-4226-krishnan-tech_CVE-2023-4226-POC.md) 🔴 ✅

**名称:** CVE-2023-4226-Chamilo LMS-远程代码执行  
**类型:** 文件上传  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-05-02  
**POC仓库:** [CVE-2023-4226-POC](https://github.com/krishnan-tech/CVE-2023-4226-POC)  

---

### [CVE-2023-4226](CVE-2023-4226-SkyW4r33x_CVE-2023-4226.md) 🔴 ✅

**名称:** CVE-2023-4226-Chamilo-LMS-远程代码执行  
**类型:** 未授权文件上传  
**风险:** 高危，远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-05-02  
**POC仓库:** [CVE-2023-4226](https://github.com/SkyW4r33x/CVE-2023-4226)  

---

### [CVE-2025-31161](CVE-2025-31161-ibrahimsql_CVE-2025-31161.md) 🔴 ✅

**名称:** CVE-2025-31161 CrushFTP 身份验证绕过  
**类型:** 身份验证绕过  
**风险:** 高危，可能导致完全系统控制  
**投毒风险:** 10%  
**发现时间:** 2025-05-01  
**POC仓库:** [CVE-2025-31161](https://github.com/ibrahimsql/CVE-2025-31161)  

---

### [CVE-2025-24054](CVE-2025-24054-S4mma3l_CVE-2025-24054.md) 🟡 ✅

**名称:** CVE-2025-24054-NTLM Hash Disclosure Spoofing  
**类型:** NTLM哈希泄露欺骗  
**风险:** 中危，可能导致凭据泄露和网络欺骗  
**投毒风险:** 5%  
**发现时间:** 2025-05-01  
**POC仓库:** [CVE-2025-24054](https://github.com/S4mma3l/CVE-2025-24054)  

---

### [CVE-2023-40355](CVE-2023-40355-ace-83_CVE-2023-40355.md) 🟡 ✅

**名称:** CVE-2023-40355-Axigen WebMail-XSS  
**类型:** XSS  
**风险:** 中危，可能导致敏感信息泄露、会话劫持或恶意脚本执行  
**投毒风险:** 10%  
**发现时间:** 2025-05-01  
**POC仓库:** [CVE-2023-40355](https://github.com/ace-83/CVE-2023-40355)  

---

### [CVE-2025-44228](CVE-2025-44228-Caztemaz_Office-Exploit-Cve2025-Xml-Doc-Docx-Rce-Builder-Fud.md) 🔴 ✅

**名称:** CVE-2025-44228 - Office Macro RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，允许攻击者完全控制受害者系统  
**投毒风险:** 30%  
**发现时间:** 2025-05-01  
**POC仓库:** [Office-Exploit-Cve2025-Xml-Doc-Docx-Rce-Builder-Fud](https://github.com/Caztemaz/Office-Exploit-Cve2025-Xml-Doc-Docx-Rce-Builder-Fud)  

---

### [CVE-2025-44228](CVE-2025-44228-Caztemaz_Lnk-Exploit-FileBinder-Certificate-Spoofer-Reg-Doc-Cve-Rce.md) 🔴 ✅

**名称:** CVE-2021-44228/CVE-2025-44228 - Log4Shell RCE / LNK Exploit  
**类型:** 远程代码执行 (RCE) / LNK文件利用  
**风险:** 高危，可能导致服务器完全控制/客户端执行恶意代码  
**投毒风险:** 60%  
**发现时间:** 2025-05-01  
**POC仓库:** [Lnk-Exploit-FileBinder-Certificate-Spoofer-Reg-Doc-Cve-Rce](https://github.com/Caztemaz/Lnk-Exploit-FileBinder-Certificate-Spoofer-Reg-Doc-Cve-Rce)  

---

### [CVE-2025-12654](CVE-2025-12654-Yuweixn_Anydesk-Exploit-CVE-2025-12654-RCE-Builder.md) 🔴 ✅

**名称:** AnyDesk Exploit - 多种漏洞集合  
**类型:** 远程代码执行 (RCE), 身份验证绕过, DLL劫持, DLL注入, 权限管理缺陷, 信息泄露  
**风险:** 高危，可能导致远程代码执行，敏感信息泄露，系统权限提升，完全控制受害者系统  
**投毒风险:** 60%  
**发现时间:** 2025-05-01  
**POC仓库:** [Anydesk-Exploit-CVE-2025-12654-RCE-Builder](https://github.com/Yuweixn/Anydesk-Exploit-CVE-2025-12654-RCE-Builder)  

---

### [CVE-2024-31317](CVE-2024-31317-JadeByteZen_CVE-2024-31317-PoC-Deployer.md) 🔴 ✅

**名称:** CVE-2024-31317-Android Zygote Deserialization  
**类型:** 权限提升  
**风险:** 高危，可导致任意代码执行和权限提升  
**投毒风险:** 10%  
**发现时间:** 2025-05-01  
**POC仓库:** [CVE-2024-31317-PoC-Deployer](https://github.com/JadeByteZen/CVE-2024-31317-PoC-Deployer)  

---

### [CVE-2024-31317](CVE-2024-31317-mianliupindao_CVE-2024-31317-PoC-Deployer.md) 🔴 ✅

**名称:** CVE-2024-31317 Android ZygoteProcess 反序列化漏洞  
**类型:** 反序列化漏洞导致提权  
**风险:** 高危，本地提权到任意应用权限  
**投毒风险:** 70%  
**发现时间:** 2025-05-01  
**POC仓库:** [CVE-2024-31317-PoC-Deployer](https://github.com/mianliupindao/CVE-2024-31317-PoC-Deployer)  

---

### [CVE-2025-20029](CVE-2025-20029-mbadanoiu_CVE-2025-20029.md) 🔴 ✅

**名称:** CVE-2025-20029: F5 BIG-IP iControl REST 和 tmsh 命令注入漏洞  
**类型:** 命令注入  
**风险:** 高危，可能导致远程代码执行，获取 root 权限  
**投毒风险:** 10%  
**发现时间:** 2025-05-01  
**POC仓库:** [CVE-2025-20029](https://github.com/mbadanoiu/CVE-2025-20029)  

---

### [CVE-2025-20029](CVE-2025-20029-schoi1337_CVE-2025-20029-simulation.md) 🔴 ✅

**名称:** CVE-2025-20029-BIG-IP-命令注入  
**类型:** 命令注入  
**风险:** 高危，允许已认证的攻击者执行任意系统命令，可能导致完全控制系统  
**投毒风险:** 10%  
**发现时间:** 2025-05-01  
**POC仓库:** [CVE-2025-20029-simulation](https://github.com/schoi1337/CVE-2025-20029-simulation)  

---


## 🔍 快速查找

- [按CVE编号查找](../../by-cve/)
- [返回2025年总览](../README.md)
- [返回总索引](../../README.md)

---

*本文档由 VulnWatchdog 自动生成 @ 2025-11-26 13:32*
