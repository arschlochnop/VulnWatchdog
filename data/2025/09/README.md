# 2025年09月漏洞情报汇总

> 📅 统计周期: 2025-09-01 ~ 2025-09-30
> 📊 新增漏洞: **594** 个
> 🔥 高危漏洞: **513** 个

---

## 📊 漏洞类型分布

| 类型 | 数量 | 占比 |
|------|------|------|
| 远程代码执行 | 65 | 10.9% |
| 路径遍历 | 37 | 6.2% |
| 远程代码执行 (RCE) | 30 | 5.1% |
| 权限提升 | 25 | 4.2% |
| SQL注入 | 21 | 3.5% |
| 反序列化漏洞 | 19 | 3.2% |
| 命令注入 | 17 | 2.9% |
| 缓冲区溢出 | 15 | 2.5% |
| 目录遍历 | 12 | 2.0% |
| 身份验证绕过 | 12 | 2.0% |

---

## 📋 详细列表

### [CVE-2025-56514](CVE-2025-56514-Kov404_CVE-2025-56514.md) 🟡 ✅

**名称:** CVE-2025-56514-Fiora Chat Application-XSS  
**类型:** XSS  
**风险:** 中危，可能导致用户信息泄露和恶意脚本执行  
**投毒风险:** 10%  
**发现时间:** 2025-09-30  
**POC仓库:** [CVE-2025-56514](https://github.com/Kov404/CVE-2025-56514)  

---

### [CVE-2025-56515](CVE-2025-56515-Kov404_CVE-2025-56515.md) 🟡 ✅

**名称:** CVE-2025-56515-Fiora Chat Application-XSS  
**类型:** XSS  
**风险:** 中危，可能导致会话劫持、权限提升等攻击  
**投毒风险:** 0%  
**发现时间:** 2025-09-30  
**POC仓库:** [CVE-2025-56515](https://github.com/Kov404/CVE-2025-56515)  

---

### [CVE-2025-57389](CVE-2025-57389-amalcew_CVE-2025-57389.md) 🟡 ✅

**名称:** CVE-2025-57389 - OpenWRT Luci Reflected XSS  
**类型:** Reflected XSS  
**风险:** 中危，可能导致会话劫持和账户接管  
**投毒风险:** 10%  
**发现时间:** 2025-09-30  
**POC仓库:** [CVE-2025-57389](https://github.com/amalcew/CVE-2025-57389)  

---

### [CVE-2025-43300](CVE-2025-43300-Dark-life944_CVE-2025.md) 🔴 ✅

**名称:** CVE-2025-43300-Apple ImageIO框架DNG图像处理内存损坏漏洞  
**类型:** 内存损坏  
**风险:** 高危，可能导致任意代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-09-30  
**POC仓库:** [CVE-2025](https://github.com/Dark-life944/CVE-2025)  

---

### [CVE-2025-43300](CVE-2025-43300-ticofookfook_CVE-2025-43300.md) 🔴 ✅

**名称:** CVE-2025-43300-macOS/iOS-图像处理内存破坏  
**类型:** 内存破坏 (Out-of-bounds Write)  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-09-30  
**POC仓库:** [CVE-2025-43300](https://github.com/ticofookfook/CVE-2025-43300)  

---

### [CVE-2024-32019](CVE-2024-32019-hexared_CVE-2024-32019_poc.md) 🔴 ✅

**名称:** CVE-2024-32019-Netdata-ndsudo本地提权  
**类型:** 本地权限提升  
**风险:** 高危，允许低权限用户获得root权限  
**投毒风险:** 1%  
**发现时间:** 2025-09-30  
**POC仓库:** [CVE-2024-32019_poc](https://github.com/hexared/CVE-2024-32019_poc)  

---

### [CVE-2017-7269](CVE-2017-7269-eliuha_webdav_exploit.md) 🔴 ✅

**名称:** CVE-2017-7269 - Microsoft IIS 6.0 WebDAV Buffer Overflow  
**类型:** 缓冲区溢出  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-09-30  
**POC仓库:** [webdav_exploit](https://github.com/eliuha/webdav_exploit)  

---

### [CVE-2017-7269](CVE-2017-7269-caicai1355_CVE-2017-7269-exploit.md) 🔴 ✅

**名称:** CVE-2017-7269-IIS 6.0 WebDAV Buffer Overflow  
**类型:** 缓冲区溢出  
**风险:** 高危，远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-09-30  
**POC仓库:** [CVE-2017-7269-exploit](https://github.com/caicai1355/CVE-2017-7269-exploit)  

---

### [CVE-2017-7269](CVE-2017-7269-zcgonvh_cve-2017-7269.md) 🔴 ✅

**名称:** CVE-2017-7269 Microsoft IIS WebDav ScStoragePathFromUrl Overflow  
**类型:** 缓冲区溢出  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-09-30  
**POC仓库:** [cve-2017-7269](https://github.com/zcgonvh/cve-2017-7269)  

---

### [CVE-2017-7269](CVE-2017-7269-ThanHuuTuan_CVE-2017-7269.md) 🔴 ✅

**名称:** CVE-2017-7269 - Microsoft IIS 6.0 WebDAV 缓冲区溢出  
**类型:** 缓冲区溢出  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-09-30  
**POC仓库:** [CVE-2017-7269](https://github.com/ThanHuuTuan/CVE-2017-7269)  

---

### [CVE-2017-7269](CVE-2017-7269-slimpagey_IIS_6.0_WebDAV_Ruby.md) 🔴 ✅

**名称:** CVE-2017-7269  
**类型:** 缓冲区溢出  
**风险:** 高危，允许远程攻击者执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-09-30  
**POC仓库:** [IIS_6.0_WebDAV_Ruby](https://github.com/slimpagey/IIS_6.0_WebDAV_Ruby)  

---

### [CVE-2017-7269](CVE-2017-7269-homjxi0e_cve-2017-7269.md) 🔴 ✅

**名称:** CVE-2017-7269 - Microsoft IIS 6.0 WebDAV 缓冲区溢出  
**类型:** 缓冲区溢出  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-09-30  
**POC仓库:** [cve-2017-7269](https://github.com/homjxi0e/cve-2017-7269)  

---

### [CVE-2017-7269](CVE-2017-7269-zcgonvh_cve-2017-7269-tool.md) 🔴 ✅

**名称:** CVE-2017-7269-Microsoft IIS 6.0 WebDAV Buffer Overflow  
**类型:** 缓冲区溢出  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-09-30  
**POC仓库:** [cve-2017-7269-tool](https://github.com/zcgonvh/cve-2017-7269-tool)  

---

### [CVE-2017-7269](CVE-2017-7269-Al1ex_CVE-2017-7269.md) 🔴 ✅

**名称:** CVE-2017-7269 Microsoft IIS WebDav ScStoragePathFromUrl Overflow  
**类型:** 缓冲区溢出  
**风险:** 高危，允许远程攻击者执行任意代码  
**投毒风险:** 0%  
**发现时间:** 2025-09-30  
**POC仓库:** [CVE-2017-7269](https://github.com/Al1ex/CVE-2017-7269)  

---

### [CVE-2017-7269](CVE-2017-7269-lcatro_CVE-2017-7269-Echo-PoC.md) 🔴 ✅

**名称:** CVE-2017-7269-IIS 6.0-缓冲区溢出  
**类型:** 缓冲区溢出  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-09-30  
**POC仓库:** [CVE-2017-7269-Echo-PoC](https://github.com/lcatro/CVE-2017-7269-Echo-PoC)  

---

### [CVE-2017-7269](CVE-2017-7269-h3x0v3rl0rd_CVE-2017-7269.md) 🔴 ✅

**名称:** CVE-2017-7269-IIS6-缓冲区溢出  
**类型:** 缓冲区溢出  
**风险:** 高危，允许远程攻击者执行任意代码  
**投毒风险:** 0%  
**发现时间:** 2025-09-30  
**POC仓库:** [CVE-2017-7269](https://github.com/h3x0v3rl0rd/CVE-2017-7269)  

---

### [CVE-2017-7269](CVE-2017-7269-g0rx_iis6-exploit-2017-CVE-2017-7269.md) 🔴 ✅

**名称:** CVE-2017-7269-IIS 6.0 WebDAV 缓冲区溢出  
**类型:** 缓冲区溢出  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-09-30  
**POC仓库:** [iis6-exploit-2017-CVE-2017-7269](https://github.com/g0rx/iis6-exploit-2017-CVE-2017-7269)  

---

### [CVE-2017-7269](CVE-2017-7269-Cappricio-Securities_CVE-2017-7269.md) 🔴 ✅

**名称:** CVE-2017-7269 - Microsoft IIS 6.0 WebDAV 缓冲区溢出  
**类型:** 缓冲区溢出  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-09-30  
**POC仓库:** [CVE-2017-7269](https://github.com/Cappricio-Securities/CVE-2017-7269)  

---

### [CVE-2017-7269](CVE-2017-7269-VanishedPeople_CVE-2017-7269.md) 🔴 ✅

**名称:** CVE-2017-7269 - Microsoft IIS 6.0 WebDAV Buffer Overflow  
**类型:** 缓冲区溢出  
**风险:** 高危，允许远程攻击者执行任意代码  
**投毒风险:** 0%  
**发现时间:** 2025-09-30  
**POC仓库:** [CVE-2017-7269](https://github.com/VanishedPeople/CVE-2017-7269)  

---

### [CVE-2017-7269](CVE-2017-7269-geniuszly_CVE-2017-7269.md) 🔴 ✅

**名称:** CVE-2017-7269 - Microsoft IIS 6.0 WebDAV 缓冲区溢出  
**类型:** 缓冲区溢出  
**风险:** 高危，远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-09-30  
**POC仓库:** [CVE-2017-7269](https://github.com/geniuszly/CVE-2017-7269)  

---

### [CVE-2017-7269](CVE-2017-7269-nika0x38_CVE-2017-7269.md) 🔴 ✅

**名称:** CVE-2017-7269 - Microsoft IIS 6.0 WebDAV 缓冲区溢出  
**类型:** 缓冲区溢出  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-09-30  
**POC仓库:** [CVE-2017-7269](https://github.com/nika0x38/CVE-2017-7269)  

---

### [CVE-2025-41244](CVE-2025-41244-rxerium_CVE-2025-41244.md) 🔴 ✅

**名称:** CVE-2025-41244-VMware本地权限提升  
**类型:** 本地权限提升  
**风险:** 高危，可使非特权本地用户获得root权限  
**投毒风险:** 0%  
**发现时间:** 2025-09-30  
**POC仓库:** [CVE-2025-41244](https://github.com/rxerium/CVE-2025-41244)  

---

### [CVE-2017-9822](CVE-2017-9822-murataydemir_CVE-2017-9822.md) 🔴 ✅

**名称:** CVE-2017-9822 DotNetNuke Cookie Deserialization RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-09-30  
**POC仓库:** [CVE-2017-9822](https://github.com/murataydemir/CVE-2017-9822)  

---

### [CVE-2017-9822](CVE-2017-9822-Tnot123_cve-2017-9822.md) 🔴 ✅

**名称:** CVE-2017-9822 DotNetNuke Cookie 反序列化 RCE  
**类型:** 反序列化漏洞  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-09-30  
**POC仓库:** [cve-2017-9822](https://github.com/Tnot123/cve-2017-9822)  

---

### [CVE-2025-55780](CVE-2025-55780-ISH2YU_CVE-2025-55780.md) 🔴 ✅

**名称:** CVE-2025-55780-MuPDF-空指针解引用  
**类型:** 空指针解引用  
**风险:** 高危，可能导致拒绝服务  
**投毒风险:** 0%  
**发现时间:** 2025-09-30  
**POC仓库:** [CVE-2025-55780](https://github.com/ISH2YU/CVE-2025-55780)  

---

### [CVE-2025-48799](CVE-2025-48799-gmh5225_CVE-2025-48799-.md) 🔴 ✅

**名称:** CVE-2025-48799  
**类型:** 特权提升  
**风险:** 高危，本地权限提升  
**投毒风险:** 5%  
**发现时间:** 2025-09-30  
**POC仓库:** [CVE-2025-48799-](https://github.com/gmh5225/CVE-2025-48799-)  

---

### [CVE-2025-57529](CVE-2025-57529-songqb-xx_CVE-2025-57529.md) 🔴 ✅

**名称:** CPAS审计管理信息系统SQL注入漏洞  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露和数据库被控制  
**投毒风险:** 1%  
**发现时间:** 2025-09-30  
**POC仓库:** [CVE-2025-57529](https://github.com/songqb-xx/CVE-2025-57529)  

---

### [CVE-2025-32444](CVE-2025-32444-stuxbench_vLLM-CVE-2025-32444.md)  ✅

**名称:** CVE-2025-32444-vLLM-RCE  
**类型:** 反序列化漏洞  
**风险:** 严重，可能导致远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-09-30  
**POC仓库:** [vLLM-CVE-2025-32444](https://github.com/stuxbench/vLLM-CVE-2025-32444)  

---

### [CVE-2019-3396](CVE-2019-3396-tno01_cve-2019-3396.md) 🔴 ✅

**名称:** CVE-2019-3396-Atlassian Confluence-服务器端模板注入  
**类型:** 服务器端模板注入 (SSTI)  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-09-30  
**POC仓库:** [cve-2019-3396](https://github.com/tno01/cve-2019-3396)  

---

### [CVE-2011-2553](CVE-2011-2553-carlosrpastrana_cve-2011-2553.md) 🔴 ✅

**名称:** CVE-2011-2553 - vsftpd 2.3.4 Backdoor Command Execution  
**类型:** 命令执行  
**风险:** 高危，可获得服务器root权限  
**投毒风险:** 10%  
**发现时间:** 2025-09-30  
**POC仓库:** [cve-2011-2553](https://github.com/carlosrpastrana/cve-2011-2553)  

---

### [CVE-2025-32463](CVE-2025-32463-AC8999_CVE-2025-32463.md) 🔴 ✅

**名称:** CVE-2025-32463-Sudo-本地提权  
**类型:** 本地提权  
**风险:** 高危，本地用户可获取root权限  
**投毒风险:** 10%  
**发现时间:** 2025-09-30  
**POC仓库:** [CVE-2025-32463](https://github.com/AC8999/CVE-2025-32463)  

---

### [CVE-2023-40289](CVE-2023-40289-s-hamann_CVE-2023-40289.md) 🔴 ✅

**名称:** CVE-2023-40289 - Supermicro BMC IPMI 命令注入  
**类型:** 命令注入  
**风险:** 高危，允许拥有BMC管理权限的攻击者提升权限  
**投毒风险:** 10%  
**发现时间:** 2025-09-29  
**POC仓库:** [CVE-2023-40289](https://github.com/s-hamann/CVE-2023-40289)  

---

### [CVE-2025-8088](CVE-2025-8088-haspread_CVE-2025-8088.md) 🔴 ✅

**名称:** CVE-2025-8088-WinRAR路径遍历  
**类型:** 路径遍历  
**风险:** 高危，允许攻击者执行任意代码  
**投毒风险:** 70%  
**发现时间:** 2025-09-29  
**POC仓库:** [CVE-2025-8088](https://github.com/haspread/CVE-2025-8088)  

---

### [CVE-2025-8518](CVE-2025-8518-maestro-ant_Vvveb-CMS-CVE-2025-8518.md) 🔴 ✅

**名称:** CVE-2025-8518-Vvveb-代码注入  
**类型:** 代码注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-09-29  
**POC仓库:** [Vvveb-CMS-CVE-2025-8518](https://github.com/maestro-ant/Vvveb-CMS-CVE-2025-8518)  

---

### [CVE-2016-10708](CVE-2016-10708-lggcs_CVE-2016-10708.md) 🟡 ✅

**名称:** CVE-2016-10708-OpenSSH-拒绝服务  
**类型:** 拒绝服务 (DoS)  
**风险:** 中危，导致服务不可用  
**投毒风险:** 0%  
**发现时间:** 2025-09-29  
**POC仓库:** [CVE-2016-10708](https://github.com/lggcs/CVE-2016-10708)  

---

### [CVE-2025-3248](CVE-2025-3248-Kiraly07_Demo_CVE-2025-3248.md) 🔴 ✅

**名称:** CVE-2025-3248-Langflow-RCE  
**类型:** 远程代码执行  
**风险:** 高危，允许未经身份验证的远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-09-29  
**POC仓库:** [Demo_CVE-2025-3248](https://github.com/Kiraly07/Demo_CVE-2025-3248)  

---

### [CVE-2025-11077](CVE-2025-11077-byteReaper77_CVE-2025-11077.md) 🔴 ✅

**名称:** CVE-2025-11077-Campcodes Online Learning Management System-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露  
**投毒风险:** 10%  
**发现时间:** 2025-09-29  
**POC仓库:** [CVE-2025-11077](https://github.com/byteReaper77/CVE-2025-11077)  

---

### [CVE-2024-47051](CVE-2024-47051-mallo-m_CVE-2024-47051.md) 🔴 

**名称:** CVE-2024-47051 - Mautic 远程代码执行和文件删除  
**类型:** 远程代码执行 (RCE) 和 路径遍历文件删除  
**风险:** 高危，可能导致服务器完全控制、数据丢失和拒绝服务  
**投毒风险:** 5%  
**发现时间:** 2025-09-29  
**POC仓库:** [CVE-2024-47051](https://github.com/mallo-m/CVE-2024-47051)  

---

### [CVE-2024-47051](CVE-2024-47051-hyeonyeonglee_CVE-2024-47051.md) 🔴 ✅

**名称:** CVE-2024-47051-Mautic-RCE & 文件删除  
**类型:** 远程代码执行 (RCE) & 路径遍历文件删除  
**风险:** 高危，可能导致服务器完全控制和数据泄露  
**投毒风险:** 10%  
**发现时间:** 2025-09-29  
**POC仓库:** [CVE-2024-47051](https://github.com/hyeonyeonglee/CVE-2024-47051)  

---

### [CVE-2025-9267](CVE-2025-9267-Tiger3080_CVE-2025-9267.md) 🔴 ✅

**名称:** CVE-2025-9267-Seagate Toolkit-DLL劫持  
**类型:** DLL劫持  
**风险:** 高危，可导致任意代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-09-29  
**POC仓库:** [CVE-2025-9267](https://github.com/Tiger3080/CVE-2025-9267)  

---

### [CVE-2022-33679](CVE-2022-33679-Amulab_CVE-2022-33679.md) 🔴 ✅

**名称:** CVE-2022-33679 Windows Kerberos 权限提升漏洞  
**类型:** 权限提升  
**风险:** 高危，可能允许未经身份验证的攻击者提升权限  
**投毒风险:** 30%  
**发现时间:** 2025-09-28  
**POC仓库:** [CVE-2022-33679](https://github.com/Amulab/CVE-2022-33679)  

---

### [CVE-2022-33679](CVE-2022-33679-Blyth0He_CVE-2022-33679.md) 🔴 ✅

**名称:** CVE-2022-33679 Windows Kerberos 权限提升漏洞  
**类型:** 权限提升  
**风险:** 高危，可能导致域权限提升  
**投毒风险:** 20%  
**发现时间:** 2025-09-28  
**POC仓库:** [CVE-2022-33679](https://github.com/Blyth0He/CVE-2022-33679)  

---

### [CVE-2022-33679](CVE-2022-33679-Bdenneu_CVE-2022-33679.md) 🔴 ✅

**名称:** CVE-2022-33679 Windows Kerberos 权限提升漏洞  
**类型:** 权限提升  
**风险:** 高危，可能导致权限提升，控制域环境  
**投毒风险:** 10%  
**发现时间:** 2025-09-28  
**POC仓库:** [CVE-2022-33679](https://github.com/Bdenneu/CVE-2022-33679)  

---

### [CVE-2022-33679](CVE-2022-33679-soy-oreocato_CVE-2022-33679_Checker.md) 🔴 ✅

**名称:** CVE-2022-33679 Windows Kerberos 权限提升漏洞  
**类型:** 权限提升  
**风险:** 高危，允许未经身份验证的攻击者提升权限  
**投毒风险:** 1%  
**发现时间:** 2025-09-28  
**POC仓库:** [CVE-2022-33679_Checker](https://github.com/soy-oreocato/CVE-2022-33679_Checker)  

---

### [CVE-2018-18441](CVE-2018-18441-bayazid-bit_CVE-2018-18441-exploit.md) 🟡 ✅

**名称:** CVE-2018-18441-D-Link DCS系列摄像头信息泄露  
**类型:** 信息泄露  
**风险:** 中危，泄露敏感信息  
**投毒风险:** 0%  
**发现时间:** 2025-09-28  
**POC仓库:** [CVE-2018-18441-exploit](https://github.com/bayazid-bit/CVE-2018-18441-exploit)  

---

### [CVE-2025-59251](CVE-2025-59251-allinsthon_CVE-2025-59251.md) 🔴 

**名称:** CVE-2025-59251 Microsoft Edge (Chromium-based) Remote Code Execution Vulnerability  
**类型:** Remote Code Execution  
**风险:** 高危，可能允许远程攻击者在受害者系统上执行任意代码。  
**投毒风险:** 5%  
**发现时间:** 2025-09-28  
**POC仓库:** [CVE-2025-59251](https://github.com/allinsthon/CVE-2025-59251)  

---

### [CVE-2025-56708](CVE-2025-56708-xkaneiki_rtty_CVE-2025-56708-CVE-2025-56709.md) 🔴 ✅

**名称:** CVE-2025-56709&CVE-2025-56708 - rtty 缓冲区溢出&未授权文件上传  
**类型:** 缓冲区溢出 & 未授权文件上传  
**风险:** 高危，可能导致拒绝服务，任意文件上传，甚至远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-09-28  
**POC仓库:** [rtty_CVE-2025-56708-CVE-2025-56709](https://github.com/xkaneiki/rtty_CVE-2025-56708-CVE-2025-56709)  

---

### [CVE-2025-56807](CVE-2025-56807-aqwainfosec_CVE-2025-56807.md) 🔴 ✅

**名称:** CVE-2025-56807 - FairSketch RISE Ultimate Project Manager & CRM Stored XSS  
**类型:** 存储型跨站脚本 (Stored XSS)  
**风险:** 高危，可能导致会话劫持和数据泄露  
**投毒风险:** 0%  
**发现时间:** 2025-09-28  
**POC仓库:** [CVE-2025-56807](https://github.com/aqwainfosec/CVE-2025-56807)  

---

### [CVE-2022-36537](CVE-2022-36537-agnihackers_CVE-2022-36537-EXPLOIT.md) 🔴 ✅

**名称:** CVE-2022-36537-ZK Framework-信息泄露/RCE  
**类型:** 信息泄露/远程代码执行  
**风险:** 高危，可能导致敏感信息泄露和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-09-28  
**POC仓库:** [CVE-2022-36537-EXPLOIT](https://github.com/agnihackers/CVE-2022-36537-EXPLOIT)  

---

### [CVE-2022-36537](CVE-2022-36537-Malwareman007_CVE-2022-36537.md) 🔴 ✅

**名称:** CVE-2022-36537-ZK Framework-信息泄露/RCE  
**类型:** 信息泄露/远程代码执行  
**风险:** 高危，可能导致敏感信息泄露和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-09-28  
**POC仓库:** [CVE-2022-36537](https://github.com/Malwareman007/CVE-2022-36537)  

---

### [CVE-2022-36537](CVE-2022-36537-ethan-repo-lab4b6_CVE-2022-36537.md) 🔴 ✅

**名称:** CVE-2022-36537 - ZK Framework AuUploader 信息泄露与RCE  
**类型:** 信息泄露/远程代码执行  
**风险:** 高危，可导致敏感信息泄露和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-09-28  
**POC仓库:** [CVE-2022-36537](https://github.com/ethan-repo-lab4b6/CVE-2022-36537)  

---

### [CVE-2009-2265](CVE-2009-2265-nika0x38_CVE-2009-2265.md) 🔴 ✅

**名称:** CVE-2009-2265 - FCKeditor 目录遍历漏洞  
**类型:** 目录遍历  
**风险:** 高危，可能导致任意文件创建和远程代码执行  
**投毒风险:** 2%  
**发现时间:** 2025-09-27  
**POC仓库:** [CVE-2009-2265](https://github.com/nika0x38/CVE-2009-2265)  

---

### [CVE-2025-20333](CVE-2025-20333-callinston_CVE-2025-20333.md) 🔴 ✅

**名称:** CVE-2025-20333-Cisco ASA/FTD-WebVPN远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致设备完全控制  
**投毒风险:** 20%  
**发现时间:** 2025-09-27  
**POC仓库:** [CVE-2025-20333](https://github.com/callinston/CVE-2025-20333)  

---

### [CVE-2025-56764](CVE-2025-56764-Remenis_CVE-2025-56764-trivision-nc227wf.md) 🔴 ✅

**名称:** CVE-2025-56764-Trivision NC-227WF 认证绕过和用户名枚举  
**类型:** 认证绕过/用户名枚举  
**风险:** 高危，可能导致未授权访问和敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-09-27  
**POC仓库:** [CVE-2025-56764-trivision-nc227wf](https://github.com/Remenis/CVE-2025-56764-trivision-nc227wf)  

---

### [CVE-2025-10035](CVE-2025-10035-orange0Mint_CVE-2025-10035_GoAnywhere.md) 🔴 

**名称:** CVE-2025-10035-GoAnywhere MFT-反序列化导致命令注入  
**类型:** 反序列化漏洞  
**风险:** 高危，远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-09-27  
**POC仓库:** [CVE-2025-10035_GoAnywhere](https://github.com/orange0Mint/CVE-2025-10035_GoAnywhere)  

---

### [CVE-2025-39596](CVE-2025-39596-Nxploited_CVE-2025-39596.md) 🔴 ✅

**名称:** CVE-2025-39596-Quentn WP-权限提升漏洞  
**类型:** 权限提升  
**风险:** 高危，攻击者可利用该漏洞获取管理员权限，控制整个WordPress站点。  
**投毒风险:** 20%  
**发现时间:** 2025-09-27  
**POC仓库:** [CVE-2025-39596](https://github.com/Nxploited/CVE-2025-39596)  

---

### [CVE-2025-59843](CVE-2025-59843-At0mXploit_CVE-2025-59843-CVE-2025-59932.md) 🔴 ✅

**名称:** CVE-2025-59843 & CVE-2025-59932 - FlagForgeCTF 信息泄露和未授权资源操作  
**类型:** 信息泄露 (CVE-2025-59843) 和 未授权操作 (CVE-2025-59932)  
**风险:** 中危/高危 (取决于CVE-2025-59932是否可利用)  
**投毒风险:** 0%  
**发现时间:** 2025-09-27  
**POC仓库:** [CVE-2025-59843-CVE-2025-59932](https://github.com/At0mXploit/CVE-2025-59843-CVE-2025-59932)  

---

### [CVE-2025-5304](CVE-2025-5304-Nxploited_CVE-2025-5304.md) 🔴 ✅

**名称:** CVE-2025-5304 - PT Project Notebooks 未授权特权提升  
**类型:** 特权提升  
**风险:** 高危，允许未授权用户提升为管理员权限  
**投毒风险:** 0%  
**发现时间:** 2025-09-27  
**POC仓库:** [CVE-2025-5304](https://github.com/Nxploited/CVE-2025-5304)  

---

### [CVE-2025-4606](CVE-2025-4606-UcenHaxor07_CVE-2025-4606.md) 🔴 ✅

**名称:** CVE-2025-4606 - Sala - Startup & SaaS WordPress Theme 未授权密码重置/账户接管漏洞  
**类型:** 未授权密码重置/账户接管  
**风险:** 高危，允许未经身份验证的攻击者更改包括管理员在内的任意用户密码，从而获得账户访问权限。  
**投毒风险:** 0%  
**发现时间:** 2025-09-27  
**POC仓库:** [CVE-2025-4606](https://github.com/UcenHaxor07/CVE-2025-4606)  

---

### [CVE-2025-3515](CVE-2025-3515-robertskimengote_lab-cve-2025-3515.md) 🔴 ✅

**名称:** CVE-2025-3515 - Drag and Drop Multiple File Upload for Contact Form 7 - 任意文件上传  
**类型:** 任意文件上传  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-09-26  
**POC仓库:** [lab-cve-2025-3515](https://github.com/robertskimengote/lab-cve-2025-3515)  

---

### [CVE-2025-31161](CVE-2025-31161-Teexo_CVE-2025-31161.md)  ✅

**名称:** CVE-2025-31161 CrushFTP Authentication Bypass  
**类型:** 身份验证绕过  
**风险:** 严重，可能导致完全系统接管  
**投毒风险:** 10%  
**发现时间:** 2025-09-26  
**POC仓库:** [CVE-2025-31161](https://github.com/Teexo/CVE-2025-31161)  

---

### [CVE-2025-56795](CVE-2025-56795-B1tBreaker_CVE-2025-56795.md) 🟡 ✅

**名称:** CVE-2025-56795-Mealie-存储型XSS  
**类型:** 存储型XSS  
**风险:** 中危，可能导致账户劫持、信息泄露或恶意脚本执行  
**投毒风险:** 0%  
**发现时间:** 2025-09-26  
**POC仓库:** [CVE-2025-56795](https://github.com/B1tBreaker/CVE-2025-56795)  

---

### [CVE-2025-5419](CVE-2025-5419-somprasong-tukman_CVE-2025-5419.md) 🔴 ✅

**名称:** CVE-2025-5419  
**类型:** V8引擎越界读写漏洞  
**风险:** 高危，可能导致堆损坏、代码执行、沙箱逃逸  
**投毒风险:** 80%  
**发现时间:** 2025-09-26  
**POC仓库:** [CVE-2025-5419](https://github.com/somprasong-tukman/CVE-2025-5419)  

---

### [CVE-2018-7600](CVE-2018-7600-tea-celikik_Drupal-Exploit-Lab.md) 🔴 ✅

**名称:** CVE-2018-7600 Drupalgeddon2  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，允许未经身份验证的远程攻击者执行任意代码，完全控制受影响的Drupal站点。  
**投毒风险:** 5%  
**发现时间:** 2025-09-26  
**POC仓库:** [Drupal-Exploit-Lab](https://github.com/tea-celikik/Drupal-Exploit-Lab)  

---

### [CVE-2025-55817](CVE-2025-55817-5qu1n7_CVE-2025-55817.md) 🟡 ✅

**名称:** Nitro GraphQL XSS漏洞  
**类型:** 跨站脚本攻击 (XSS)  
**风险:** 中危，可能导致信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-09-26  
**POC仓库:** [CVE-2025-55817](https://github.com/5qu1n7/CVE-2025-55817)  

---

### [CVE-2023-36802](CVE-2023-36802-rahul0xkr_Reproducing-CVE-2023-36802.md) 🔴 ✅

**名称:** CVE-2023-36802 - Microsoft Streaming Service Proxy Elevation of Privilege Vulnerability  
**类型:** 权限提升 (Elevation of Privilege)  
**风险:** 高危，可导致本地权限提升至SYSTEM  
**投毒风险:** 10%  
**发现时间:** 2025-09-26  
**POC仓库:** [Reproducing-CVE-2023-36802](https://github.com/rahul0xkr/Reproducing-CVE-2023-36802)  

---

### [CVE-2025-39866](CVE-2025-39866-byteReaper77_CVE-2025-39866.md) 🔴 ✅

**名称:** CVE-2025-39866 - Linux Kernel Use-After-Free  
**类型:** Use-After-Free  
**风险:** 高危，可能导致系统崩溃、拒绝服务或权限提升  
**投毒风险:** 1%  
**发现时间:** 2025-09-26  
**POC仓库:** [CVE-2025-39866](https://github.com/byteReaper77/CVE-2025-39866)  

---

### [CVE-2025-8088](CVE-2025-8088-kyomber_CVE-2025-8088.md) 🔴 ✅

**名称:** CVE-2025-8088 WinRAR Path Traversal  
**类型:** Path Traversal  
**风险:** 高危，允许攻击者通过精心制作的压缩文件执行任意代码  
**投毒风险:** 5%  
**发现时间:** 2025-09-26  
**POC仓库:** [CVE-2025-8088](https://github.com/kyomber/CVE-2025-8088)  

---

### [CVE-2025-56383](CVE-2025-56383-zer0t0_CVE-2025-56383-Proof-of-Concept.md) 🔴 ✅

**名称:** Notepad++ v8.8.3 DLL劫持漏洞  
**类型:** DLL劫持  
**风险:** 高危，可能导致任意代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-09-26  
**POC仓库:** [CVE-2025-56383-Proof-of-Concept](https://github.com/zer0t0/CVE-2025-56383-Proof-of-Concept)  

---

### [CVE-2025-6384](CVE-2025-6384-maestro-ant_CrafterCMS-CVE-2025-6384.md) 🔴 ✅

**名称:** CVE-2025-6384-CrafterCMS-Groovy沙箱绕过RCE  
**类型:** 远程代码执行（RCE）  
**风险:** 高危，可导致服务器被完全控制  
**投毒风险:** 5%  
**发现时间:** 2025-09-26  
**POC仓库:** [CrafterCMS-CVE-2025-6384](https://github.com/maestro-ant/CrafterCMS-CVE-2025-6384)  

---

### [CVE-2025-20352](CVE-2025-20352-scadastrangelove_CVE-2025-20352.md) 🔴 ✅

**名称:** CVE-2025-20352 Cisco IOS/IOS XE SNMP 栈溢出漏洞  
**类型:** 栈溢出  
**风险:** 高危，低权限可导致DoS，高权限可导致远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-09-25  
**POC仓库:** [CVE-2025-20352](https://github.com/scadastrangelove/CVE-2025-20352)  

---

### [CVE-2025-9998](CVE-2025-9998-balajigund_Research-on-CVE-2025-9998.md) 🟡 

**名称:** CVE-2025-9998-PcVue-拒绝服务  
**类型:** 拒绝服务  
**风险:** 中危，可能导致应用停止服务  
**投毒风险:** 0%  
**发现时间:** 2025-09-25  
**POC仓库:** [Research-on-CVE-2025-9998](https://github.com/balajigund/Research-on-CVE-2025-9998)  

---

### [CVE-2024-38399](CVE-2024-38399-Shreyas-Penkar_CVE-2024-38399.md) 🔴 

**名称:** CVE-2024-38399  
**类型:** Use After Free  
**风险:** 高危，可能导致任意代码执行或拒绝服务  
**投毒风险:** 1%  
**发现时间:** 2025-09-25  
**POC仓库:** [CVE-2024-38399](https://github.com/Shreyas-Penkar/CVE-2024-38399)  

---

### [CVE-2020-5248](CVE-2020-5248-Mkway_CVE-2020-5248.md) 🔴 ✅

**名称:** CVE-2020-5248 - GLPI 默认加密密钥漏洞  
**类型:** 硬编码密钥  
**风险:** 高危，可能导致敏感数据泄露  
**投毒风险:** 1%  
**发现时间:** 2025-09-25  
**POC仓库:** [CVE-2020-5248](https://github.com/Mkway/CVE-2020-5248)  

---

### [CVE-2020-5248](CVE-2020-5248-venomnis_CVE-2020-5248.md) 🔴 ✅

**名称:** CVE-2020-5248 - GLPI 默认密钥解密漏洞  
**类型:** 硬编码凭据  
**风险:** 高危，可能导致敏感数据泄露  
**投毒风险:** 0%  
**发现时间:** 2025-09-25  
**POC仓库:** [CVE-2020-5248](https://github.com/venomnis/CVE-2020-5248)  

---

### [CVE-2025-22294](CVE-2025-22294-mirmeweu_cve-2025-22294.md) 🟡 

**名称:** CVE-2025-22294 - WordPress Custom Field For WP Job Manager plugin <= 1.3 Reflected XSS  
**类型:** Reflected XSS  
**风险:** 中危  
**投毒风险:** 0%  
**发现时间:** 2025-09-25  
**POC仓库:** [cve-2025-22294](https://github.com/mirmeweu/cve-2025-22294)  

---

### [CVE-2025-51495](CVE-2025-51495-cainiao159357_CVE-2025-51495.md) 🔴 ✅

**名称:** Mongoose WebSocket Integer Overflow Vulnerability  
**类型:** Integer Overflow  
**风险:** 高危，可能导致内存损坏、程序崩溃或远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-09-25  
**POC仓库:** [CVE-2025-51495](https://github.com/cainiao159357/CVE-2025-51495)  

---

### [CVE-2025-54726](CVE-2025-54726-RandomRobbieBF_CVE-2025-54726.md) 🔴 ✅

**名称:** CVE-2025-54726-JS Archive List-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露  
**投毒风险:** 10%  
**发现时间:** 2025-09-25  
**POC仓库:** [CVE-2025-54726](https://github.com/RandomRobbieBF/CVE-2025-54726)  

---

### [CVE-2025-49132](CVE-2025-49132-WebSafety-2tina_CVE-2025-49132.md) 🔴 ✅

**名称:** CVE-2025-49132-Pterodactyl Panel-RCE  
**类型:** 远程代码执行  
**风险:** 高危，可完全控制服务器  
**投毒风险:** 0%  
**发现时间:** 2025-09-25  
**POC仓库:** [CVE-2025-49132](https://github.com/WebSafety-2tina/CVE-2025-49132)  

---

### [CVE-2017-5638](CVE-2017-5638-kaylertee_Computer-Security-Equifax-2017.md) 🔴 ✅

**名称:** CVE-2017-5638 Apache Struts远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 20%  
**发现时间:** 2025-09-25  
**POC仓库:** [Computer-Security-Equifax-2017](https://github.com/kaylertee/Computer-Security-Equifax-2017)  

---

### [CVE-2022-35583](CVE-2022-35583-Malayke_CVE-2022-35583-Pandoc-SSRF-POC.md) 🔴 ✅

**名称:** CVE-2022-35583 wkhtmlTOpdf SSRF  
**类型:** SSRF  
**风险:** 高危，允许攻击者获取内部资产并可能控制整个基础设施  
**投毒风险:** 5%  
**发现时间:** 2025-09-25  
**POC仓库:** [CVE-2022-35583-Pandoc-SSRF-POC](https://github.com/Malayke/CVE-2022-35583-Pandoc-SSRF-POC)  

---

### [CVE-2025-8088](CVE-2025-8088-lucyna77_winrar-malware-exploit.md) 🔴 ✅

**名称:** CVE-2025-8088-WinRAR路径遍历漏洞  
**类型:** 路径遍历  
**风险:** 高危，可能导致任意代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-09-25  
**POC仓库:** [winrar-malware-exploit](https://github.com/lucyna77/winrar-malware-exploit)  

---

### [CVE-2025-57174](CVE-2025-57174-semaja22_CVE-2025-57174.md) 🔴 ✅

**名称:** CVE-2025-57174 - Siklu EtherHaul Series - Unauthenticated Remote Command Execution  
**类型:** 远程命令执行  
**风险:** 高危，允许未授权的攻击者执行任意命令  
**投毒风险:** 0%  
**发现时间:** 2025-09-24  
**POC仓库:** [CVE-2025-57174](https://github.com/semaja22/CVE-2025-57174)  

---

### [CVE-2025-57176](CVE-2025-57176-semaja22_CVE-2025-57176.md) 🔴 ✅

**名称:** CVE-2025-57176 - Siklu EtherHaul Series - Unauthenticated Arbitrary File Upload  
**类型:** 未授权任意文件上传  
**风险:** 高危，可能导致远程代码执行、设备控制  
**投毒风险:** 0%  
**发现时间:** 2025-09-24  
**POC仓库:** [CVE-2025-57176](https://github.com/semaja22/CVE-2025-57176)  

---

### [CVE-2022-24434](CVE-2022-24434-nayankadamm_CVE-2022-24434_POC.md) 🔴 ✅

**名称:** CVE-2022-24434-dicer-DoS  
**类型:** 拒绝服务 (DoS)  
**风险:** 高危，可能导致服务中断  
**投毒风险:** 5%  
**发现时间:** 2025-09-24  
**POC仓库:** [CVE-2022-24434_POC](https://github.com/nayankadamm/CVE-2022-24434_POC)  

---

### [CVE-2024-32002](CVE-2024-32002-JoaoLeonello_cve-2024-32002-poc.md) 🔴 ✅

**名称:** CVE-2024-32002 - Git Submodule Remote Code Execution  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可导致远程代码执行，完全控制受影响系统  
**投毒风险:** 10%  
**发现时间:** 2025-09-24  
**POC仓库:** [cve-2024-32002-poc](https://github.com/JoaoLeonello/cve-2024-32002-poc)  

---

### [CVE-2023-34233](CVE-2023-34233-nayankadamm_CVE-2023-34233_Proof_OF_Concept.md) 🔴 ✅

**名称:** CVE-2023-34233-Snowflake Python Connector-命令注入  
**类型:** 命令注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-09-24  
**POC仓库:** [CVE-2023-34233_Proof_OF_Concept](https://github.com/nayankadamm/CVE-2023-34233_Proof_OF_Concept)  

---

### [CVE-2024-32002](CVE-2024-32002-blackninja23_CVE-2024-32002.md) 🔴 ✅

**名称:** CVE-2024-32002-Git-RCE  
**类型:** 远程代码执行  
**风险:** 高危，可能导致完全控制受影响的系统  
**投毒风险:** 10%  
**发现时间:** 2025-09-24  
**POC仓库:** [CVE-2024-32002](https://github.com/blackninja23/CVE-2024-32002)  

---

### [CVE-2024-32002](CVE-2024-32002-NishanthAnand21_CVE-2024-32002-PoC.md) 🔴 ✅

**名称:** CVE-2024-32002-Git-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，允许攻击者在受害者机器上执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-09-24  
**POC仓库:** [CVE-2024-32002-PoC](https://github.com/NishanthAnand21/CVE-2024-32002-PoC)  

---

### [CVE-2024-32002](CVE-2024-32002-Masamuneee_hook.md) 🔴 ✅

**名称:** CVE-2024-32002-Git远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 20%  
**发现时间:** 2025-09-24  
**POC仓库:** [hook](https://github.com/Masamuneee/hook)  

---

### [CVE-2024-32002](CVE-2024-32002-Basyaact_CVE-2024-32002-PoC_Chinese.md)  ✅

**名称:** CVE-2024-32002 - Git 递归克隆远程代码执行漏洞  
**类型:** 远程代码执行  
**风险:** 严重，可能导致远程代码执行和系统完全控制  
**投毒风险:** 5%  
**发现时间:** 2025-09-24  
**POC仓库:** [CVE-2024-32002-PoC_Chinese](https://github.com/Basyaact/CVE-2024-32002-PoC_Chinese)  

---

### [CVE-2024-32002](CVE-2024-32002-bonnettheo_CVE-2024-32002.md)  ✅

**名称:** CVE-2024-32002 - Git Submodule RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 严重，可能导致远程代码执行和系统完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-09-24  
**POC仓库:** [CVE-2024-32002](https://github.com/bonnettheo/CVE-2024-32002)  

---

### [CVE-2024-32002](CVE-2024-32002-sysonlai_CVE-2024-32002-hook.md) 🔴 ✅

**名称:** CVE-2024-32002 Git RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-09-24  
**POC仓库:** [CVE-2024-32002-hook](https://github.com/sysonlai/CVE-2024-32002-hook)  

---

### [CVE-2024-32002](CVE-2024-32002-TSY244_CVE-2024-32002-git-rce-father-poc.md) 🔴 ✅

**名称:** CVE-2024-32002-Git-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-09-24  
**POC仓库:** [CVE-2024-32002-git-rce-father-poc](https://github.com/TSY244/CVE-2024-32002-git-rce-father-poc)  

---

### [CVE-2024-32002](CVE-2024-32002-SpycioKon_CVE-2024-32002.md) 🔴 ✅

**名称:** CVE-2024-32002-Git-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行和系统控制  
**投毒风险:** 10%  
**发现时间:** 2025-09-24  
**POC仓库:** [CVE-2024-32002](https://github.com/SpycioKon/CVE-2024-32002)  

---

### [CVE-2024-32002](CVE-2024-32002-charlesgargasson_CVE-2024-32002.md) 🔴 ✅

**名称:** CVE-2024-32002-Git-RCE  
**类型:** 远程代码执行  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-09-24  
**POC仓库:** [CVE-2024-32002](https://github.com/charlesgargasson/CVE-2024-32002)  

---

### [CVE-2024-32002](CVE-2024-32002-daemon-reconfig_CVE-2024-32002.md) 🔴 ✅

**名称:** CVE-2024-32002  
**类型:** 远程代码执行  
**风险:** 高危，允许攻击者在受害者机器上执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-09-24  
**POC仓库:** [CVE-2024-32002](https://github.com/daemon-reconfig/CVE-2024-32002)  

---

### [CVE-2024-32002](CVE-2024-32002-chrisWalker11_running-CVE-2024-32002-locally-for-tesing.md) 🔴 ✅

**名称:** CVE-2024-32002 - Git 递归克隆远程代码执行漏洞  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-09-24  
**POC仓库:** [running-CVE-2024-32002-locally-for-tesing](https://github.com/chrisWalker11/running-CVE-2024-32002-locally-for-tesing)  

---

### [CVE-2024-32002](CVE-2024-32002-sanan2004_CVE-2024-32002.md) 🔴 ✅

**名称:** CVE-2024-32002 Git Submodule RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-09-24  
**POC仓库:** [CVE-2024-32002](https://github.com/sanan2004/CVE-2024-32002)  

---

### [CVE-2024-32002](CVE-2024-32002-FlojBoj_CVE-2024-32002.md) 🔴 ✅

**名称:** CVE-2024-32002-Git-RCE  
**类型:** 远程代码执行  
**风险:** 高危，允许攻击者在目标机器上执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-09-24  
**POC仓库:** [CVE-2024-32002](https://github.com/FlojBoj/CVE-2024-32002)  

---

### [CVE-2024-32002](CVE-2024-32002-th4s1s_CVE-2024-32002-PoC.md)  ✅

**名称:** CVE-2024-32002-Git远程代码执行  
**类型:** 远程代码执行(RCE)  
**风险:** 严重，可能导致完全控制受害者系统  
**投毒风险:** 10%  
**发现时间:** 2025-09-24  
**POC仓库:** [CVE-2024-32002-PoC](https://github.com/th4s1s/CVE-2024-32002-PoC)  

---

### [CVE-2024-32002](CVE-2024-32002-Masamuneee_CVE-2024-32002-POC.md) 🔴 ✅

**名称:** CVE-2024-32002 Git Submodule RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，允许攻击者在受害者机器上执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-09-24  
**POC仓库:** [CVE-2024-32002-POC](https://github.com/Masamuneee/CVE-2024-32002-POC)  

---

### [CVE-2024-32002](CVE-2024-32002-XiaomingX_cve-2024-32002-poc.md) 🔴 ✅

**名称:** CVE-2024-32002-Git-RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-09-24  
**POC仓库:** [cve-2024-32002-poc](https://github.com/XiaomingX/cve-2024-32002-poc)  

---

### [CVE-2024-32002](CVE-2024-32002-grecosamuel_CVE-2024-32002.md) 🔴 ✅

**名称:** CVE-2024-32002 - Git Submodule RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，允许攻击者在受害者机器上执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-09-24  
**POC仓库:** [CVE-2024-32002](https://github.com/grecosamuel/CVE-2024-32002)  

---

### [CVE-2024-32002](CVE-2024-32002-Julian-gmz_hook_CVE-2024-32002.md) 🔴 ✅

**名称:** CVE-2024-32002 - Git 递归克隆远程代码执行漏洞  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可导致完全控制受害者机器  
**投毒风险:** 20%  
**发现时间:** 2025-09-24  
**POC仓库:** [hook_CVE-2024-32002](https://github.com/Julian-gmz/hook_CVE-2024-32002)  

---

### [CVE-2024-32002](CVE-2024-32002-ashutosh0408_CVE-2024-32002.md) 🔴 ✅

**名称:** CVE-2024-32002-Git-RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-09-24  
**POC仓库:** [CVE-2024-32002](https://github.com/ashutosh0408/CVE-2024-32002)  

---

### [CVE-2024-32002](CVE-2024-32002-ashutosh0408_Cve-2024-32002-poc.md) 🔴 ✅

**名称:** CVE-2024-32002 Git Submodule RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致远程代码执行和系统完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-09-24  
**POC仓库:** [Cve-2024-32002-poc](https://github.com/ashutosh0408/Cve-2024-32002-poc)  

---

### [CVE-2025-2294](CVE-2025-2294-iteride_CVE-2025-2294.md) 🔴 ✅

**名称:** CVE-2025-2294 - Kubio AI Page Builder LFI  
**类型:** 本地文件包含 (LFI)  
**风险:** 高危，可能导致敏感数据泄露和远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-09-24  
**POC仓库:** [CVE-2025-2294](https://github.com/iteride/CVE-2025-2294)  

---

### [CVE-2017-12611](CVE-2017-12611-zeynepsilao_CVE-2017-12611_Exploit.md) 🔴 ✅

**名称:** CVE-2017-12611 - Apache Struts Freemarker RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-09-24  
**POC仓库:** [CVE-2017-12611_Exploit](https://github.com/zeynepsilao/CVE-2017-12611_Exploit)  

---

### [CVE-2025-56819](CVE-2025-56819-xyyzxc_CVE-2025-56819.md) 🔴 ✅

**名称:** CVE-2025-56819-Datart-JDBC注入  
**类型:** JDBC注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-09-24  
**POC仓库:** [CVE-2025-56819](https://github.com/xyyzxc/CVE-2025-56819)  

---

### [CVE-2025-10184](CVE-2025-10184-yuuouu_OnePush-CVE-2025-10184.md) 🔴 ✅

**名称:** CVE-2025-10184-OnePlus OxygenOS Telephony Provider Permission Bypass  
**类型:** 权限绕过/SQL注入  
**风险:** 高危，可能导致SMS/MMS数据泄露，破坏MFA  
**投毒风险:** 10%  
**发现时间:** 2025-09-24  
**POC仓库:** [OnePush-CVE-2025-10184](https://github.com/yuuouu/OnePush-CVE-2025-10184)  

---

### [CVE-2025-10184](CVE-2025-10184-People-11_CVE-2025-10184_PoC.md) 🔴 ✅

**名称:** CVE-2025-10184-OnePlus OxygenOS-SMS读取  
**类型:** 权限绕过/SQL注入  
**风险:** 高危，可能导致敏感信息泄露，MFA绕过  
**投毒风险:** 5%  
**发现时间:** 2025-09-24  
**POC仓库:** [CVE-2025-10184_PoC](https://github.com/People-11/CVE-2025-10184_PoC)  

---

### [CVE-2025-32433](CVE-2025-32433-mirmeweu_cve-2025-32433.md) 🔴 ✅

**名称:** CVE-2025-32433 - Erlang/OTP SSH Pre-Authentication RCE  
**类型:** 远程代码执行  
**风险:** 高危，允许未经身份验证的远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-09-24  
**POC仓库:** [cve-2025-32433](https://github.com/mirmeweu/cve-2025-32433)  

---

### [CVE-2025-8088](CVE-2025-8088-pablo388_WinRAR-CVE-2025-8088-PoC-RAR.md) 🔴 ✅

**名称:** CVE-2025-8088 WinRAR Path Traversal  
**类型:** 路径遍历  
**风险:** 高危，允许攻击者执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-09-24  
**POC仓库:** [WinRAR-CVE-2025-8088-PoC-RAR](https://github.com/pablo388/WinRAR-CVE-2025-8088-PoC-RAR)  

---

### [CVE-2025-32463](CVE-2025-32463-nelissandro_CVE-2025-32463-Sudo-Chroot-Escape.md) 🔴 ✅

**名称:** CVE-2025-32463-Sudo-Chroot权限提升  
**类型:** 本地权限提升  
**风险:** 高危，允许本地用户获取root权限  
**投毒风险:** 5%  
**发现时间:** 2025-09-24  
**POC仓库:** [CVE-2025-32463-Sudo-Chroot-Escape](https://github.com/nelissandro/CVE-2025-32463-Sudo-Chroot-Escape)  

---

### [CVE-2025-55188](CVE-2025-55188-Sh3ruman_CVE-2025-55188-7z-exploit.md) 🟡 ✅

**名称:** CVE-2025-55188-7-Zip符号链接处理不当漏洞  
**类型:** 符号链接处理不当  
**风险:** 中危，可能导致任意文件写入  
**投毒风险:** 10%  
**发现时间:** 2025-09-24  
**POC仓库:** [CVE-2025-55188-7z-exploit](https://github.com/Sh3ruman/CVE-2025-55188-7z-exploit)  

---

### [CVE-2025-34100](CVE-2025-34100-hyeonyeonglee_CVE-2025-34100.md) 🔴 ✅

**名称:** CVE-2025-34100-BuilderEngine-RCE  
**类型:** 任意文件上传导致远程代码执行  
**风险:** 高危，可导致服务器完全控制  
**投毒风险:** 5%  
**发现时间:** 2025-09-24  
**POC仓库:** [CVE-2025-34100](https://github.com/hyeonyeonglee/CVE-2025-34100)  

---

### [CVE-2025-54253](CVE-2025-54253-akujedanjedon_CVE-2025-54253-Exploit-Demo.md) 🔴 ✅

**名称:** CVE-2025-54253 Adobe Experience Manager Misconfiguration  
**类型:** Misconfiguration/OGNL Injection  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 20%  
**发现时间:** 2025-09-24  
**POC仓库:** [CVE-2025-54253-Exploit-Demo](https://github.com/akujedanjedon/CVE-2025-54253-Exploit-Demo)  

---

### [CVE-2025-0133](CVE-2025-0133-adhamelhansye_CVE-2025-0133.md) 🟡 ✅

**名称:** CVE-2025-0133-PAN-OS-Reflected XSS  
**类型:** Reflected XSS  
**风险:** 中危，可能导致凭据盗窃和客户端攻击  
**投毒风险:** 0%  
**发现时间:** 2025-09-24  
**POC仓库:** [CVE-2025-0133](https://github.com/adhamelhansye/CVE-2025-0133)  

---

### [CVE-2025-2825](CVE-2025-2825-iteride_CVE-2025-2825.md) 🔴 ✅

**名称:** CVE-2025-2825-CrushFTP认证绕过  
**类型:** 认证绕过  
**风险:** 高危，可能导致数据泄露、远程代码执行和权限提升  
**投毒风险:** 10%  
**发现时间:** 2025-09-23  
**POC仓库:** [CVE-2025-2825](https://github.com/iteride/CVE-2025-2825)  

---

### [CVE-2025-29927](CVE-2025-29927-sermikr0_nextjs-middleware-auth-bypass.md) 🔴 ✅

**名称:** CVE-2025-29927-Next.js Middleware 身份验证绕过  
**类型:** 身份验证绕过  
**风险:** 高危，可能导致未授权访问和数据泄露  
**投毒风险:** 10%  
**发现时间:** 2025-09-23  
**POC仓库:** [nextjs-middleware-auth-bypass](https://github.com/sermikr0/nextjs-middleware-auth-bypass)  

---

### [CVE-2025-29927](CVE-2025-29927-amalpvatayam67_day10-nextjs-middleware-lab.md) 🔴 ✅

**名称:** CVE-2025-29927-Next.js Middleware 权限绕过  
**类型:** 权限绕过  
**风险:** 高危，可能导致未授权访问和数据泄露  
**投毒风险:** 0%  
**发现时间:** 2025-09-23  
**POC仓库:** [day10-nextjs-middleware-lab](https://github.com/amalpvatayam67/day10-nextjs-middleware-lab)  

---

### [CVE-2020-3452](CVE-2020-3452-Aviksaikat_CVE-2020-3452.md) 🔴 ✅

**名称:** CVE-2020-3452 Cisco ASA/FTD 目录遍历漏洞  
**类型:** 目录遍历  
**风险:** 高危，可能导致敏感文件泄露  
**投毒风险:** 0%  
**发现时间:** 2025-09-23  
**POC仓库:** [CVE-2020-3452](https://github.com/Aviksaikat/CVE-2020-3452)  

---

### [CVE-2025-53770](CVE-2025-53770-Michaael01_LetsDefend--SOC-342-CVE-2025-53770-SharePoint-Exploit-ToolShell.md) 🔴 ✅

**名称:** CVE-2025-53770-SharePoint-远程代码执行  
**类型:** 反序列化漏洞导致远程代码执行  
**风险:** 高危，允许未经授权的攻击者通过网络执行代码  
**投毒风险:** 0%  
**发现时间:** 2025-09-23  
**POC仓库:** [LetsDefend--SOC-342-CVE-2025-53770-SharePoint-Exploit-ToolShell](https://github.com/Michaael01/LetsDefend--SOC-342-CVE-2025-53770-SharePoint-Exploit-ToolShell)  

---

### [CVE-2025-54424](CVE-2025-54424-bejbitoilet5125521_CVE-2025-54424.md) 🔴 ✅

**名称:** CVE-2025-54424-1Panel-RCE  
**类型:** 远程代码执行(RCE)  
**风险:** 高危，未经授权的访问可能导致完全的系统控制。  
**投毒风险:** 10%  
**发现时间:** 2025-09-23  
**POC仓库:** [CVE-2025-54424](https://github.com/bejbitoilet5125521/CVE-2025-54424)  

---

### [CVE-2025-1974](CVE-2025-1974-iteride_CVE-2025-1974.md)  ✅

**名称:** CVE-2025-1974 - ingress-nginx 远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 严重，可能导致集群接管和敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-09-23  
**POC仓库:** [CVE-2025-1974](https://github.com/iteride/CVE-2025-1974)  

---

### [CVE-2020-3452](CVE-2020-3452-XDev05_CVE-2020-3452-PoC.md) 🔴 ✅

**名称:** CVE-2020-3452 Cisco ASA/FTD 目录遍历漏洞  
**类型:** 目录遍历  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 5%  
**发现时间:** 2025-09-23  
**POC仓库:** [CVE-2020-3452-PoC](https://github.com/XDev05/CVE-2020-3452-PoC)  

---

### [CVE-2020-3452](CVE-2020-3452-Loneyers_cve-2020-3452.md) 🔴 ✅

**名称:** CVE-2020-3452 - Cisco ASA/FTD Read-Only Path Traversal  
**类型:** 目录遍历  
**风险:** 高危，可能导致敏感文件泄露  
**投毒风险:** 0%  
**发现时间:** 2025-09-23  
**POC仓库:** [cve-2020-3452](https://github.com/Loneyers/cve-2020-3452)  

---

### [CVE-2020-3452](CVE-2020-3452-mr-r3b00t_CVE-2020-3452.md) 🔴 ✅

**名称:** CVE-2020-3452 Cisco ASA/FTD 目录遍历漏洞  
**类型:** 目录遍历  
**风险:** 高危，可能导致敏感文件泄露  
**投毒风险:** 0%  
**发现时间:** 2025-09-23  
**POC仓库:** [CVE-2020-3452](https://github.com/mr-r3b00t/CVE-2020-3452)  

---

### [CVE-2020-3452](CVE-2020-3452-0x5ECF4ULT_CVE-2020-3452.md) 🔴 ✅

**名称:** CVE-2020-3452 Cisco ASA/FTD 路径遍历漏洞  
**类型:** 路径遍历  
**风险:** 高危，可读取敏感文件  
**投毒风险:** 5%  
**发现时间:** 2025-09-23  
**POC仓库:** [CVE-2020-3452](https://github.com/0x5ECF4ULT/CVE-2020-3452)  

---

### [CVE-2020-3452](CVE-2020-3452-foulenzer_CVE-2020-3452.md) 🔴 ✅

**名称:** CVE-2020-3452 Cisco ASA/FTD 路径遍历漏洞  
**类型:** 路径遍历  
**风险:** 高危，允许未经身份验证的远程攻击者读取敏感文件  
**投毒风险:** 0%  
**发现时间:** 2025-09-23  
**POC仓库:** [CVE-2020-3452](https://github.com/foulenzer/CVE-2020-3452)  

---

### [CVE-2020-3452](CVE-2020-3452-PR3R00T_CVE-2020-3452-Cisco-Scanner.md) 🔴 ✅

**名称:** CVE-2020-3452 Cisco ASA/FTD 目录遍历漏洞  
**类型:** 目录遍历  
**风险:** 高危，可读取敏感文件  
**投毒风险:** 0%  
**发现时间:** 2025-09-23  
**POC仓库:** [CVE-2020-3452-Cisco-Scanner](https://github.com/PR3R00T/CVE-2020-3452-Cisco-Scanner)  

---

### [CVE-2020-3452](CVE-2020-3452-murataydemir_CVE-2020-3452.md) 🔴 ✅

**名称:** CVE-2020-3452 Cisco ASA/FTD Read-Only Path Traversal  
**类型:** 路径遍历  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-09-23  
**POC仓库:** [CVE-2020-3452](https://github.com/murataydemir/CVE-2020-3452)  

---

### [CVE-2020-3452](CVE-2020-3452-3ndG4me_CVE-2020-3452-Exploit.md) 🔴 ✅

**名称:** CVE-2020-3452 Cisco ASA/FTD 路径遍历漏洞  
**类型:** 路径遍历  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-09-23  
**POC仓库:** [CVE-2020-3452-Exploit](https://github.com/3ndG4me/CVE-2020-3452-Exploit)  

---

### [CVE-2020-3452](CVE-2020-3452-Gh0st0ne_http-vuln-cve2020-3452.nse.md) 🔴 ✅

**名称:** CVE-2020-3452 Cisco ASA/FTD Read-Only Path Traversal  
**类型:** 路径遍历  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-09-23  
**POC仓库:** [http-vuln-cve2020-3452.nse](https://github.com/Gh0st0ne/http-vuln-cve2020-3452.nse)  

---

### [CVE-2020-3452](CVE-2020-3452-ludy-dev_Cisco-ASA-LFI.md) 🔴 ✅

**名称:** CVE-2020-3452 Cisco ASA/FTD 路径遍历漏洞  
**类型:** 路径遍历  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-09-23  
**POC仓库:** [Cisco-ASA-LFI](https://github.com/ludy-dev/Cisco-ASA-LFI)  

---

### [CVE-2020-3452](CVE-2020-3452-grim3_CVE-2020-3452.md) 🔴 ✅

**名称:** CVE-2020-3452 Cisco ASA/FTD 路径遍历漏洞  
**类型:** 路径遍历  
**风险:** 高危，可能导致敏感文件泄露  
**投毒风险:** 0%  
**发现时间:** 2025-09-23  
**POC仓库:** [CVE-2020-3452](https://github.com/grim3/CVE-2020-3452)  

---

### [CVE-2020-3452](CVE-2020-3452-fuzzlove_Cisco-ASA-FTD-Web-Services-Traversal.md) 🔴 ✅

**名称:** CVE-2020-3452 Cisco ASA/FTD Web Services Read-Only Path Traversal  
**类型:** 目录遍历  
**风险:** 高危，允许未授权远程攻击者读取敏感文件  
**投毒风险:** 0%  
**发现时间:** 2025-09-23  
**POC仓库:** [Cisco-ASA-FTD-Web-Services-Traversal](https://github.com/fuzzlove/Cisco-ASA-FTD-Web-Services-Traversal)  

---

### [CVE-2020-3452](CVE-2020-3452-faisalfs10x_Cisco-CVE-2020-3452-shodan-scanner.md) 🔴 ✅

**名称:** CVE-2020-3452-Cisco ASA/FTD 路径遍历漏洞  
**类型:** 路径遍历  
**风险:** 高危，可读取敏感文件  
**投毒风险:** 10%  
**发现时间:** 2025-09-23  
**POC仓库:** [Cisco-CVE-2020-3452-shodan-scanner](https://github.com/faisalfs10x/Cisco-CVE-2020-3452-shodan-scanner)  

---

### [CVE-2020-3452](CVE-2020-3452-paran0id34_CVE-2020-3452.md) 🔴 ✅

**名称:** CVE-2020-3452 - Cisco ASA/FTD 目录遍历  
**类型:** 目录遍历  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-09-23  
**POC仓库:** [CVE-2020-3452](https://github.com/paran0id34/CVE-2020-3452)  

---

### [CVE-2020-3452](CVE-2020-3452-sujaygr8_CVE-2020-3452.md) 🔴 ✅

**名称:** CVE-2020-3452-Cisco ASA/FTD 目录遍历漏洞  
**类型:** 目录遍历  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-09-23  
**POC仓库:** [CVE-2020-3452](https://github.com/sujaygr8/CVE-2020-3452)  

---

### [CVE-2020-3452](CVE-2020-3452-darklotuskdb_CISCO-CVE-2020-3452-Scanner-Exploiter.md) 🔴 ✅

**名称:** CVE-2020-3452-Cisco ASA/FTD Read-Only Path Traversal  
**类型:** 目录遍历  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 1%  
**发现时间:** 2025-09-23  
**POC仓库:** [CISCO-CVE-2020-3452-Scanner-Exploiter](https://github.com/darklotuskdb/CISCO-CVE-2020-3452-Scanner-Exploiter)  

---

### [CVE-2020-3452](CVE-2020-3452-Veids_CVE-2020-3452_auto.md) 🔴 ✅

**名称:** CVE-2020-3452 Cisco ASA/FTD 路径遍历漏洞  
**类型:** 路径遍历  
**风险:** 高危，可能导致敏感文件泄露  
**投毒风险:** 10%  
**发现时间:** 2025-09-23  
**POC仓库:** [CVE-2020-3452_auto](https://github.com/Veids/CVE-2020-3452_auto)  

---

### [CVE-2020-3452](CVE-2020-3452-iveresk_cve-2020-3452.md) 🔴 ✅

**名称:** CVE-2020-3452 Cisco ASA/FTD 目录遍历漏洞  
**类型:** 目录遍历  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 5%  
**发现时间:** 2025-09-23  
**POC仓库:** [cve-2020-3452](https://github.com/iveresk/cve-2020-3452)  

---

### [CVE-2020-3452](CVE-2020-3452-cygenta_CVE-2020-3452.md) 🔴 ✅

**名称:** CVE-2020-3452 Cisco ASA/FTD 路径遍历漏洞  
**类型:** 路径遍历  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 5%  
**发现时间:** 2025-09-23  
**POC仓库:** [CVE-2020-3452](https://github.com/cygenta/CVE-2020-3452)  

---

### [CVE-2020-3452](CVE-2020-3452-Cappricio-Securities_CVE-2020-3452.md) 🔴 ✅

**名称:** CVE-2020-3452-Cisco ASA/FTD 路径遍历漏洞  
**类型:** 路径遍历  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-09-23  
**POC仓库:** [CVE-2020-3452](https://github.com/Cappricio-Securities/CVE-2020-3452)  

---

### [CVE-2020-3452](CVE-2020-3452-abrewer251_CVE-2020-3452_Cisco_ASA_PathTraversal.md) 🔴 ✅

**名称:** CVE-2020-3452 Cisco ASA/FTD 路径遍历漏洞  
**类型:** 路径遍历  
**风险:** 高危，可能导致敏感文件泄露  
**投毒风险:** 0%  
**发现时间:** 2025-09-23  
**POC仓库:** [CVE-2020-3452_Cisco_ASA_PathTraversal](https://github.com/abrewer251/CVE-2020-3452_Cisco_ASA_PathTraversal)  

---

### [CVE-2025-43372](CVE-2025-43372-allinsthon_CVE-2025-43372.md) 🟡 ✅

**名称:** CVE-2025-43372-Apple-媒体文件处理漏洞  
**类型:** 输入验证漏洞  
**风险:** 中危，可能导致应用意外终止或进程内存损坏  
**投毒风险:** 0%  
**发现时间:** 2025-09-23  
**POC仓库:** [CVE-2025-43372](https://github.com/allinsthon/CVE-2025-43372)  

---

### [CVE-2025-26399](CVE-2025-26399-rxerium_CVE-2025-26399.md) 🔴 ✅

**名称:** CVE-2025-26399 - SolarWinds Web Help Desk 反序列化RCE  
**类型:** 反序列化远程代码执行  
**风险:** 高危，允许未授权攻击者在主机上执行任意命令  
**投毒风险:** 0%  
**发现时间:** 2025-09-23  
**POC仓库:** [CVE-2025-26399](https://github.com/rxerium/CVE-2025-26399)  

---

### [CVE-2025-26399](CVE-2025-26399-h4xnz_CVE-2025-26399-Exploit.md) 🔴 

**名称:** CVE-2025-26399-SolarWinds Web Help Desk 反序列化RCE  
**类型:** 反序列化远程代码执行  
**风险:** 高危，允许未授权用户执行任意代码  
**投毒风险:** 5%  
**发现时间:** 2025-09-23  
**POC仓库:** [CVE-2025-26399-Exploit](https://github.com/h4xnz/CVE-2025-26399-Exploit)  

---

### [CVE-2025-30406](CVE-2025-30406-jaydenb546_CVE-2025-30406.md) 🔴 ✅

**名称:** CVE-2025-30406-Gladinet CentreStack-反序列化漏洞  
**类型:** 反序列化漏洞  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 20%  
**发现时间:** 2025-09-23  
**POC仓库:** [CVE-2025-30406](https://github.com/jaydenb546/CVE-2025-30406)  

---

### [CVE-2025-31200](CVE-2025-31200-serundengsapi_CVE-2025-31200-iOS-AudioConverter-RCE.md) 🔴 ✅

**名称:** CVE-2025-31200 – iOS AudioConverterService Zero-Click RCE  
**类型:** 内存损坏/远程代码执行  
**风险:** 高危，允许攻击者通过恶意音频文件远程执行代码，访问敏感数据，并可能导致拒绝服务。  
**投毒风险:** 10%  
**发现时间:** 2025-09-23  
**POC仓库:** [CVE-2025-31200-iOS-AudioConverter-RCE](https://github.com/serundengsapi/CVE-2025-31200-iOS-AudioConverter-RCE)  

---

### [CVE-2025-32463](CVE-2025-32463-DaadaAyoze_CVE-2025-32463-lab.md) 🔴 ✅

**名称:** CVE-2025-32463-Sudo-本地提权  
**类型:** 本地提权  
**风险:** 高危，本地用户可获取root权限  
**投毒风险:** 10%  
**发现时间:** 2025-09-23  
**POC仓库:** [CVE-2025-32463-lab](https://github.com/DaadaAyoze/CVE-2025-32463-lab)  

---

### [CVE-2023-6933](CVE-2023-6933-w2xim3_CVE-2023-6933.md) 🔴 ✅

**名称:** CVE-2023-6933 - WordPress Better Search Replace Plugin PHP对象注入  
**类型:** PHP对象注入  
**风险:** 高危，可能导致任意文件删除、敏感数据泄露或远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-09-23  
**POC仓库:** [CVE-2023-6933](https://github.com/w2xim3/CVE-2023-6933)  

---

### [CVE-2023-6933](CVE-2023-6933-Trex96_vulnerable-bsr-lab-CVE-2023-6933.md) 🔴 ✅

**名称:** CVE-2023-6933 - WordPress Better Search Replace Plugin PHP 对象注入  
**类型:** PHP 对象注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-09-23  
**POC仓库:** [vulnerable-bsr-lab-CVE-2023-6933](https://github.com/Trex96/vulnerable-bsr-lab-CVE-2023-6933)  

---

### [CVE-2025-32432](CVE-2025-32432-bambooqj_CVE-2025-32432.md) 🔴 ✅

**名称:** CVE-2025-32432-CraftCMS-RCE  
**类型:** 远程代码执行  
**风险:** 高危，未经身份验证的远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-09-23  
**POC仓库:** [CVE-2025-32432](https://github.com/bambooqj/CVE-2025-32432)  

---

### [CVE-2025-53770](CVE-2025-53770-fentnttntnt_CVE-2025-53770.md) 🔴 ✅

**名称:** CVE-2025-53770-Microsoft SharePoint Server-RCE  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 5%  
**发现时间:** 2025-09-23  
**POC仓库:** [CVE-2025-53770](https://github.com/fentnttntnt/CVE-2025-53770)  

---

### [CVE-2025-53770](CVE-2025-53770-ziisenpai_CVE-2025-53770-Scanner.md) 🔴 ✅

**名称:** CVE-2025-53770-Microsoft SharePoint Server 远程代码执行漏洞  
**类型:** 反序列化漏洞  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 30%  
**发现时间:** 2025-09-23  
**POC仓库:** [CVE-2025-53770-Scanner](https://github.com/ziisenpai/CVE-2025-53770-Scanner)  

---

### [CVE-2025-53770](CVE-2025-53770-taqiaferdianshah_CVE-2025-53770.md)  ✅

**名称:** CVE-2025-53770 - Microsoft SharePoint Server 远程代码执行漏洞  
**类型:** 反序列化漏洞  
**风险:** 严重，可导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-09-23  
**POC仓库:** [CVE-2025-53770](https://github.com/taqiaferdianshah/CVE-2025-53770)  

---

### [CVE-2025-53770](CVE-2025-53770-yashz0007_CVE-2025-53770-Exploit.md) 🔴 ✅

**名称:** CVE-2025-53770-SharePoint远程代码执行漏洞  
**类型:** 反序列化  
**风险:** 高危，允许未经授权的攻击者通过网络执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-09-23  
**POC仓库:** [CVE-2025-53770-Exploit](https://github.com/yashz0007/CVE-2025-53770-Exploit)  

---

### [CVE-2023-3824](CVE-2023-3824-jhonnybonny_CVE-2023-3824.md) 🔴 ✅

**名称:** CVE-2023-3824 - PHP Phar 堆栈缓冲区溢出  
**类型:** 堆栈缓冲区溢出  
**风险:** 高危，可能导致内存损坏或远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-09-23  
**POC仓库:** [CVE-2023-3824](https://github.com/jhonnybonny/CVE-2023-3824)  

---

### [CVE-2023-3824](CVE-2023-3824-bluefish3r_poc-cve.md) 🔴 

**名称:** CVE-2023-3824 - PHP Phar 堆栈缓冲区溢出  
**类型:** 堆栈缓冲区溢出  
**风险:** 高危，可能导致内存破坏或远程代码执行（RCE）  
**投毒风险:** 10%  
**发现时间:** 2025-09-23  
**POC仓库:** [poc-cve](https://github.com/bluefish3r/poc-cve)  

---

### [CVE-2023-3824](CVE-2023-3824-dadosneurais_cve-2023-3824.md) 🔴 ✅

**名称:** CVE-2023-3824-PHP-phar_dir_read栈缓冲区溢出  
**类型:** 栈缓冲区溢出  
**风险:** 高危，可能导致内存破坏或远程代码执行（RCE）  
**投毒风险:** 0%  
**发现时间:** 2025-09-23  
**POC仓库:** [cve-2023-3824](https://github.com/dadosneurais/cve-2023-3824)  

---

### [CVE-2025-51005](CVE-2025-51005-sy460129_CVE-2025-51005.md) 🔴 ✅

**名称:** CVE-2025-51005 – tcpreplay Heap Buffer Overflow  
**类型:** Heap Buffer Overflow  
**风险:** 高危，可能导致拒绝服务(DoS)  
**投毒风险:** 10%  
**发现时间:** 2025-09-23  
**POC仓库:** [CVE-2025-51005](https://github.com/sy460129/CVE-2025-51005)  

---

### [CVE-2025-32463](CVE-2025-32463-no-speech-to-text_CVE-2025-32463.md) 🔴 ✅

**名称:** CVE-2025-32463 - Sudo chroot 权限提升  
**类型:** 本地权限提升  
**风险:** 高危，本地用户可获得root权限  
**投毒风险:** 10%  
**发现时间:** 2025-09-23  
**POC仓库:** [CVE-2025-32463](https://github.com/no-speech-to-text/CVE-2025-32463)  

---

### [CVE-2024-21413](CVE-2024-21413-yass2400012_Email-exploit-Moniker-Link-CVE-2024-21413-.md) 🔴 ✅

**名称:** CVE-2024-21413 - Microsoft Outlook RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可导致远程代码执行，完全控制受害者系统  
**投毒风险:** 10%  
**发现时间:** 2025-09-23  
**POC仓库:** [Email-exploit-Moniker-Link-CVE-2024-21413-](https://github.com/yass2400012/Email-exploit-Moniker-Link-CVE-2024-21413-)  

---

### [CVE-2025-25257](CVE-2025-25257-kityzed2003_CVE-2025-25257.md) 🔴 ✅

**名称:** CVE-2025-25257-FortiWeb-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露、远程代码执行以及未经授权的访问  
**投毒风险:** 10%  
**发现时间:** 2025-09-22  
**POC仓库:** [CVE-2025-25257](https://github.com/kityzed2003/CVE-2025-25257)  

---

### [CVE-2025-5777](CVE-2025-5777-Lakiya673_CVE-2025-5777.md) 🔴 ✅

**名称:** CVE-2025-5777-NetScaler ADC/Gateway 内存信息泄露  
**类型:** 内存信息泄露  
**风险:** 高危，可能导致会话劫持  
**投毒风险:** 80%  
**发现时间:** 2025-09-22  
**POC仓库:** [CVE-2025-5777](https://github.com/Lakiya673/CVE-2025-5777)  

---

### [CVE-2025-48799](CVE-2025-48799-ukisshinaah_CVE-2025-48799.md) 🔴 ✅

**名称:** CVE-2025-48799 - Windows Update Service Elevation of Privilege Vulnerability  
**类型:** 特权提升  
**风险:** 高危，攻击者可以利用此漏洞提升权限到SYSTEM  
**投毒风险:** 10%  
**发现时间:** 2025-09-22  
**POC仓库:** [CVE-2025-48799](https://github.com/ukisshinaah/CVE-2025-48799)  

---

### [CVE-2015-6668](CVE-2015-6668-G01d3nW01f_CVE-2015-6668.md) 🟡 ✅

**名称:** CVE-2015-6668-Job Manager-Insecure Direct Object Reference  
**类型:** Insecure Direct Object Reference (IDOR)  
**风险:** 中危，可能导致未经授权的CV文件访问  
**投毒风险:** 0%  
**发现时间:** 2025-09-22  
**POC仓库:** [CVE-2015-6668](https://github.com/G01d3nW01f/CVE-2015-6668)  

---

### [CVE-2015-6668](CVE-2015-6668-h3x0v3rl0rd_CVE-2015-6668.md) 🟡 ✅

**名称:** CVE-2015-6668 - WordPress Job Manager Plugin CV 文件名泄露  
**类型:** 信息泄露  
**风险:** 中危，可能泄露敏感信息  
**投毒风险:** 0%  
**发现时间:** 2025-09-22  
**POC仓库:** [CVE-2015-6668](https://github.com/h3x0v3rl0rd/CVE-2015-6668)  

---

### [CVE-2015-6668](CVE-2015-6668-jimdiroffii_CVE-2015-6668.md) 🟡 ✅

**名称:** CVE-2015-6668 - WordPress Job Manager 插件 CV 文件泄露  
**类型:** 信息泄露  
**风险:** 中危，可能导致个人身份信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-09-22  
**POC仓库:** [CVE-2015-6668](https://github.com/jimdiroffii/CVE-2015-6668)  

---

### [CVE-2015-6668](CVE-2015-6668-NoTrustedx_Job-Manager-Disclosure.md) 🟡 ✅

**名称:** CVE-2015-6668 - WordPress Job Manager CV 文件名泄露  
**类型:** 信息泄露  
**风险:** 中危，可能导致个人信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-09-22  
**POC仓库:** [Job-Manager-Disclosure](https://github.com/NoTrustedx/Job-Manager-Disclosure)  

---

### [CVE-2015-6668](CVE-2015-6668-nika0x38_CVE-2015-6668.md) 🟡 ✅

**名称:** CVE-2015-6668 - WordPress Job Manager Plugin Insecure Direct Object Reference  
**类型:** Insecure Direct Object Reference (IDOR)  
**风险:** 中危，可能导致未经授权的CV文件访问  
**投毒风险:** 1%  
**发现时间:** 2025-09-22  
**POC仓库:** [CVE-2015-6668](https://github.com/nika0x38/CVE-2015-6668)  

---

### [CVE-2025-10585](CVE-2025-10585-callinston_CVE-2025-10585.md) 🔴 

**名称:** CVE-2025-10585 - Chrome V8 Type Confusion  
**类型:** 类型混淆  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-09-22  
**POC仓库:** [CVE-2025-10585](https://github.com/callinston/CVE-2025-10585)  

---

### [CVE-2025-32463](CVE-2025-32463-sarthak4399_CVE-2025-32463.md) 🔴 ✅

**名称:** CVE-2025-32463-Sudo-本地提权  
**类型:** 本地提权  
**风险:** 高危，本地用户可提升至root权限  
**投毒风险:** 0%  
**发现时间:** 2025-09-22  
**POC仓库:** [CVE-2025-32463](https://github.com/sarthak4399/CVE-2025-32463)  

---

### [CVE-2025-56311](CVE-2025-56311-wrathfulDiety_CVE-2025-56311.md) 🟡 ✅

**名称:** CVE-2025-56311: FD602GW-DX-R410 路由器 CSRF 重启漏洞  
**类型:** 跨站请求伪造 (CSRF)  
**风险:** 中危，可能导致拒绝服务  
**投毒风险:** 10%  
**发现时间:** 2025-09-22  
**POC仓库:** [CVE-2025-56311](https://github.com/wrathfulDiety/CVE-2025-56311)  

---

### [CVE-2010-2883](CVE-2010-2883-avielzecharia_CVE-2010-2883.md) 🔴 ✅

**名称:** CVE-2010-2883 Adobe Reader CoolType SING Table 栈缓冲区溢出  
**类型:** 栈缓冲区溢出  
**风险:** 高危，可导致远程代码执行或拒绝服务  
**投毒风险:** 10%  
**发现时间:** 2025-09-22  
**POC仓库:** [CVE-2010-2883](https://github.com/avielzecharia/CVE-2010-2883)  

---

### [CVE-2025-8088](CVE-2025-8088-kay0te_CVE-2025-8088.md) 🔴 ✅

**名称:** CVE-2025-8088-WinRAR路径遍历  
**类型:** 路径遍历  
**风险:** 高危，允许攻击者执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-09-22  
**POC仓库:** [CVE-2025-8088](https://github.com/kay0te/CVE-2025-8088)  

---

### [CVE-2025-59424](CVE-2025-59424-JOOJIII_CVE-2025-59424.md) 🔴 

**名称:** CVE-2025-59424 - LinkAce 存储型XSS漏洞  
**类型:** 存储型跨站脚本 (Stored XSS)  
**风险:** 高危，可能导致账户劫持、信息泄露、管理员权限获取  
**投毒风险:** 10%  
**发现时间:** 2025-09-22  
**POC仓库:** [CVE-2025-59424](https://github.com/JOOJIII/CVE-2025-59424)  

---

### [CVE-2025-40677](CVE-2025-40677-PeterGabaldon_CVE-2025-40677.md) 🔴 ✅

**名称:** CVE-2025-40677-Summar Employee Portal-SQL注入  
**类型:** SQL注入  
**风险:** 高危，允许攻击者检索、创建、更新和删除数据库内容  
**投毒风险:** 10%  
**发现时间:** 2025-09-22  
**POC仓库:** [CVE-2025-40677](https://github.com/PeterGabaldon/CVE-2025-40677)  

---

### [CVE-2025-21298](CVE-2025-21298-fy-poc_full-poc-CVE-2025_21298.md) 🔴 ✅

**名称:** CVE-2025-21298-Windows OLE Remote Code Execution  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-09-22  
**POC仓库:** [full-poc-CVE-2025_21298](https://github.com/fy-poc/full-poc-CVE-2025_21298)  

---

### [CVE-2023-1545](CVE-2023-1545-lineeralgebra_CVE-2023-1545-POC.md) 🔴 ✅

**名称:** CVE-2023-1545-Teampass-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露  
**投毒风险:** 5%  
**发现时间:** 2025-09-22  
**POC仓库:** [CVE-2023-1545-POC](https://github.com/lineeralgebra/CVE-2023-1545-POC)  

---

### [CVE-2018-7600](CVE-2018-7600-nika0x38_CVE-2018-7600.md) 🔴 ✅

**名称:** CVE-2018-7600-Drupal-RCE  
**类型:** 远程代码执行  
**风险:** 高危，允许未经身份验证的远程攻击者执行任意代码  
**投毒风险:** 0%  
**发现时间:** 2025-09-21  
**POC仓库:** [CVE-2018-7600](https://github.com/nika0x38/CVE-2018-7600)  

---

### [CVE-2024-46982](CVE-2024-46982-CodePontiff_next_js_poisoning.md) 🔴 ✅

**名称:** CVE-2024-46982 - Next.js 缓存投毒  
**类型:** 缓存投毒  
**风险:** 高危，可能导致恶意内容被缓存并提供给用户，造成钓鱼、信息篡改等风险，最终可能导致拒绝服务。  
**投毒风险:** 10%  
**发现时间:** 2025-09-21  
**POC仓库:** [next_js_poisoning](https://github.com/CodePontiff/next_js_poisoning)  

---

### [CVE-2024-46982](CVE-2024-46982-Lercas_CVE-2024-46982.md) 🔴 ✅

**名称:** CVE-2024-46982-Next.js 缓存投毒  
**类型:** 缓存投毒  
**风险:** 高危，可能导致XSS、DoS和数据泄露  
**投毒风险:** 0%  
**发现时间:** 2025-09-21  
**POC仓库:** [CVE-2024-46982](https://github.com/Lercas/CVE-2024-46982)  

---

### [CVE-2024-46982](CVE-2024-46982-melmathari_CVE-2024-46982-NUCLEI.md) 🟡 ✅

**名称:** CVE-2024-46982-Next.js Cache Poisoning  
**类型:** 缓存投毒  
**风险:** 中危，可能导致错误或恶意内容被提供给用户  
**投毒风险:** 0%  
**发现时间:** 2025-09-21  
**POC仓库:** [CVE-2024-46982-NUCLEI](https://github.com/melmathari/CVE-2024-46982-NUCLEI)  

---

### [CVE-2025-29927](CVE-2025-29927-iteride_CVE-2025-29927.md) 🔴 ✅

**名称:** CVE-2025-29927-Next.js中间件授权绕过  
**类型:** 授权绕过  
**风险:** 高危，可能导致未授权访问和数据泄露  
**投毒风险:** 10%  
**发现时间:** 2025-09-21  
**POC仓库:** [CVE-2025-29927](https://github.com/iteride/CVE-2025-29927)  

---

### [CVE-2020-0796](CVE-2020-0796-Jagadeesh7532_-CVE-2020-0796-SMBGhost-Windows-10-SMBv3-Remote-Code-Execution-Vulnerability.md) 🔴 ✅

**名称:** CVE-2020-0796 SMBGhost 远程代码执行漏洞  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行和系统控制  
**投毒风险:** 10%  
**发现时间:** 2025-09-21  
**POC仓库:** [-CVE-2020-0796-SMBGhost-Windows-10-SMBv3-Remote-Code-Execution-Vulnerability](https://github.com/Jagadeesh7532/-CVE-2020-0796-SMBGhost-Windows-10-SMBv3-Remote-Code-Execution-Vulnerability)  

---

### [CVE-2025-8088](CVE-2025-8088-Osinskitito499_CVE-2025-8088.md) 🔴 ✅

**名称:** CVE-2025-8088-WinRAR路径遍历漏洞  
**类型:** 路径遍历  
**风险:** 高危，可能导致任意代码执行  
**投毒风险:** 70%  
**发现时间:** 2025-09-21  
**POC仓库:** [CVE-2025-8088](https://github.com/Osinskitito499/CVE-2025-8088)  

---

### [CVE-2025-8088](CVE-2025-8088-m4nbun_CVE-2025-8088.md) 🔴 ✅

**名称:** CVE-2025-8088 WinRAR 路径遍历漏洞  
**类型:** 路径遍历  
**风险:** 高危，可能导致任意代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-09-21  
**POC仓库:** [CVE-2025-8088](https://github.com/m4nbun/CVE-2025-8088)  

---

### [CVE-2025-34152](CVE-2025-34152-kh4sh3i_CVE-2025-34152.md) 🔴 ✅

**名称:** CVE-2025-34152 - Shenzhen Aitemi M300 Wi-Fi Repeater OS 命令注入  
**类型:** OS 命令注入  
**风险:** 高危，可能导致远程代码执行和设备完全控制  
**投毒风险:** 5%  
**发现时间:** 2025-09-21  
**POC仓库:** [CVE-2025-34152](https://github.com/kh4sh3i/CVE-2025-34152)  

---

### [CVE-2018-13379](CVE-2018-13379-milo2012_CVE-2018-13379.md) 🔴 ✅

**名称:** CVE-2018-13379 Fortinet FortiOS/FortiProxy 路径遍历漏洞  
**类型:** 路径遍历  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 5%  
**发现时间:** 2025-09-21  
**POC仓库:** [CVE-2018-13379](https://github.com/milo2012/CVE-2018-13379)  

---

### [CVE-2018-13379](CVE-2018-13379-0xHunter_FortiOS-Credentials-Disclosure.md) 🔴 ✅

**名称:** CVE-2018-13379 Fortinet FortiOS/FortiProxy SSL VPN 路径遍历漏洞  
**类型:** 路径遍历  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-09-21  
**POC仓库:** [FortiOS-Credentials-Disclosure](https://github.com/0xHunter/FortiOS-Credentials-Disclosure)  

---

### [CVE-2018-13379](CVE-2018-13379-yukar1z0e_CVE-2018-13379.md) 🔴 ✅

**名称:** CVE-2018-13379-Fortinet-Path Traversal  
**类型:** 路径遍历  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-09-21  
**POC仓库:** [CVE-2018-13379](https://github.com/yukar1z0e/CVE-2018-13379)  

---

### [CVE-2018-13379](CVE-2018-13379-Blazz3_cve2018-13379-nmap-script.md) 🔴 ✅

**名称:** CVE-2018-13379-FortiOS/FortiProxy-路径遍历  
**类型:** 路径遍历  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 5%  
**发现时间:** 2025-09-21  
**POC仓库:** [cve2018-13379-nmap-script](https://github.com/Blazz3/cve2018-13379-nmap-script)  

---

### [CVE-2018-13379](CVE-2018-13379-pwn3z_CVE-2018-13379-FortinetVPN.md) 🔴 ✅

**名称:** CVE-2018-13379-FortinetVPN 路径遍历  
**类型:** 路径遍历  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-09-21  
**POC仓库:** [CVE-2018-13379-FortinetVPN](https://github.com/pwn3z/CVE-2018-13379-FortinetVPN)  

---

### [CVE-2018-13379](CVE-2018-13379-k4nfr3_CVE-2018-13379-Fortinet.md) 🔴 ✅

**名称:** CVE-2018-13379-Fortinet SSL VPN 路径遍历漏洞  
**类型:** 路径遍历 (Path Traversal)  
**风险:** 高危，可能导致敏感信息泄露，包括用户名密码等  
**投毒风险:** 10%  
**发现时间:** 2025-09-21  
**POC仓库:** [CVE-2018-13379-Fortinet](https://github.com/k4nfr3/CVE-2018-13379-Fortinet)  

---

### [CVE-2018-13379](CVE-2018-13379-B1anda0_CVE-2018-13379.md) 🔴 ✅

**名称:** CVE-2018-13379 - Fortinet FortiOS/FortiProxy 路径遍历漏洞  
**类型:** 路径遍历 (Path Traversal)  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-09-21  
**POC仓库:** [CVE-2018-13379](https://github.com/B1anda0/CVE-2018-13379)  

---

### [CVE-2018-13379](CVE-2018-13379-Zeop-CyberSec_fortios_vpnssl_traversal_leak.md) 🔴 ✅

**名称:** CVE-2018-13379 - Fortinet FortiOS/FortiProxy SSL VPN 路径遍历  
**类型:** 路径遍历  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-09-21  
**POC仓库:** [fortios_vpnssl_traversal_leak](https://github.com/Zeop-CyberSec/fortios_vpnssl_traversal_leak)  

---

### [CVE-2018-13379](CVE-2018-13379-nivdolgin_CVE-2018-13379.md) 🔴 ✅

**名称:** CVE-2018-13379-Fortinet-Path Traversal  
**类型:** 路径遍历  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-09-21  
**POC仓库:** [CVE-2018-13379](https://github.com/nivdolgin/CVE-2018-13379)  

---

### [CVE-2018-13379](CVE-2018-13379-jpiechowka_at-doom-fortigate.md) 🔴 ✅

**名称:** CVE-2018-13379 - Fortinet FortiOS/FortiProxy 路径遍历漏洞  
**类型:** 路径遍历  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-09-21  
**POC仓库:** [at-doom-fortigate](https://github.com/jpiechowka/at-doom-fortigate)  

---

### [CVE-2018-13379](CVE-2018-13379-kh4sh3i_CVE-2018-13379.md) 🔴 ✅

**名称:** CVE-2018-13379 - Fortinet FortiOS/FortiProxy SSL VPN 路径遍历  
**类型:** 路径遍历 (Path Traversal)  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 5%  
**发现时间:** 2025-09-21  
**POC仓库:** [CVE-2018-13379](https://github.com/kh4sh3i/CVE-2018-13379)  

---

### [CVE-2025-25257](CVE-2025-25257-segfault-it_CVE-2025-25257.md)  ✅

**名称:** CVE-2025-25257-FortiWeb-SQL注入到RCE  
**类型:** SQL注入  
**风险:** 严重，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-09-21  
**POC仓库:** [CVE-2025-25257](https://github.com/segfault-it/CVE-2025-25257)  

---

### [CVE-2025-10035](CVE-2025-10035-ThemeHackers_CVE-2025-10035.md) 🔴 ✅

**名称:** CVE-2025-10035-GoAnywhere MFT-反序列化漏洞  
**类型:** 反序列化漏洞  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-09-21  
**POC仓库:** [CVE-2025-10035](https://github.com/ThemeHackers/CVE-2025-10035)  

---

### [CVE-2025-55888](CVE-2025-55888-0xZeroSec_CVE-2025-55888.md) 🔴 ✅

**名称:** CVE-2025-55888-ARD-Stored XSS  
**类型:** Stored Cross-Site Scripting (XSS)  
**风险:** 高危，可能导致会话劫持、cookie窃取等恶意行为  
**投毒风险:** 10%  
**发现时间:** 2025-09-20  
**POC仓库:** [CVE-2025-55888](https://github.com/0xZeroSec/CVE-2025-55888)  

---

### [CVE-2025-32463](CVE-2025-32463-At0mXploit_CVE-2025-32463.md) 🔴 ✅

**名称:** CVE-2025-32463-Sudo-本地提权  
**类型:** 本地提权  
**风险:** 高危，允许本地用户获取root权限  
**投毒风险:** 5%  
**发现时间:** 2025-09-20  
**POC仓库:** [CVE-2025-32463](https://github.com/At0mXploit/CVE-2025-32463)  

---

### [CVE-2025-55886](CVE-2025-55886-0xZeroSec_CVE-2025-55886.md) 🟡 ✅

**名称:** CVE-2025-55886-ARD-IDOR  
**类型:** IDOR (Insecure Direct Object Reference)  
**风险:** 中危，可能导致未授权访问用户支付历史  
**投毒风险:** 5%  
**发现时间:** 2025-09-20  
**POC仓库:** [CVE-2025-55886](https://github.com/0xZeroSec/CVE-2025-55886)  

---

### [CVE-2024-3094](CVE-2024-3094-Titus-soc_-CVE-2024-3094-Vulnerability-Checker-Fixer-Public.md) 🔴 ✅

**名称:** CVE-2024-3094-xz-utils-供应链后门  
**类型:** 供应链攻击/后门  
**风险:** 极高危，可能导致未经授权的远程访问和控制  
**投毒风险:** 10%  
**发现时间:** 2025-09-20  
**POC仓库:** [-CVE-2024-3094-Vulnerability-Checker-Fixer-Public](https://github.com/Titus-soc/-CVE-2024-3094-Vulnerability-Checker-Fixer-Public)  

---

### [CVE-2025-55887](CVE-2025-55887-0xZeroSec_CVE-2025-55887.md) 🟡 ✅

**名称:** CVE-2025-55887 - ARD Meal Reservation Service XSS  
**类型:** 跨站脚本 (XSS)  
**风险:** 中危，可能导致会话劫持、cookie窃取以及以受害者身份执行恶意操作  
**投毒风险:** 5%  
**发现时间:** 2025-09-20  
**POC仓库:** [CVE-2025-55887](https://github.com/0xZeroSec/CVE-2025-55887)  

---

### [CVE-2025-55885](CVE-2025-55885-0xZeroSec_CVE-2025-55885.md) 🔴 ✅

**名称:** CVE-2025-55885 - ARD GEC en Ligne SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露和权限提升  
**投毒风险:** 0%  
**发现时间:** 2025-09-20  
**POC仓库:** [CVE-2025-55885](https://github.com/0xZeroSec/CVE-2025-55885)  

---

### [CVE-2025-29927](CVE-2025-29927-sdrtba_CVE-2025-29927.md) 🔴 ✅

**名称:** CVE-2025-29927-Next.js-授权绕过  
**类型:** 授权绕过  
**风险:** 高危，可能导致未经授权的访问、数据泄露和缓存投毒  
**投毒风险:** 10%  
**发现时间:** 2025-09-20  
**POC仓库:** [CVE-2025-29927](https://github.com/sdrtba/CVE-2025-29927)  

---

### [CVE-2025-10035](CVE-2025-10035-rxerium_CVE-2025-10035.md) 🔴 ✅

**名称:** CVE-2025-10035-GoAnywhere MFT-反序列化漏洞  
**类型:** 反序列化漏洞  
**风险:** 高危，可能导致命令注入和远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-09-20  
**POC仓库:** [CVE-2025-10035](https://github.com/rxerium/CVE-2025-10035)  

---

### [CVE-2025-57515](CVE-2025-57515-sanchitsahni_CVE-2025-57515.md) 🔴 ✅

**名称:** CVE-2024-57401-Uniclare Student Portal-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露、账户接管和系统入侵  
**投毒风险:** 10%  
**发现时间:** 2025-09-20  
**POC仓库:** [CVE-2025-57515](https://github.com/sanchitsahni/CVE-2025-57515)  

---

### [CVE-2025-9074](CVE-2025-9074-pucagit_CVE-2025-9074.md) 🔴 ✅

**名称:** CVE-2025-9074 Docker Desktop 本地提权/容器逃逸  
**类型:** 容器逃逸/本地提权  
**风险:** 高危，可导致容器逃逸，控制Docker Engine，甚至控制宿主机  
**投毒风险:** 1%  
**发现时间:** 2025-09-20  
**POC仓库:** [CVE-2025-9074](https://github.com/pucagit/CVE-2025-9074)  

---

### [CVE-2025-32463](CVE-2025-32463-mihnasdsad_CVE-2025-32463.md) 🔴 ✅

**名称:** CVE-2025-32463-Sudo-本地提权  
**类型:** 本地提权  
**风险:** 高危，本地用户可获取Root权限  
**投毒风险:** 1%  
**发现时间:** 2025-09-20  
**POC仓库:** [CVE-2025-32463](https://github.com/mihnasdsad/CVE-2025-32463)  

---

### [CVE-2025-32463](CVE-2025-32463-ashardev002_CVE-2025-32463_chwoot.md)  ✅

**名称:** CVE-2025-32463 Sudo 本地提权漏洞  
**类型:** 本地提权  
**风险:** 严重，本地用户可获取root权限  
**投毒风险:** 10%  
**发现时间:** 2025-09-20  
**POC仓库:** [CVE-2025-32463_chwoot](https://github.com/ashardev002/CVE-2025-32463_chwoot)  

---

### [CVE-2025-10585](CVE-2025-10585-AdityaBhatt3010_CVE-2025-10585-The-Chrome-V8-Zero-Day.md) 🔴 

**名称:** CVE-2025-10585  
**类型:** V8 JavaScript/WebAssembly引擎类型混淆漏洞  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-09-19  
**POC仓库:** [CVE-2025-10585-The-Chrome-V8-Zero-Day](https://github.com/AdityaBhatt3010/CVE-2025-10585-The-Chrome-V8-Zero-Day)  

---

### [CVE-2024-57366](CVE-2024-57366-h4ckusaur_CVE-2024-57366.md) 🔴 ✅

**名称:** CVE-2024-57366 - Fisher Price 路由器远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，允许攻击者完全控制受影响的路由器。  
**投毒风险:** 10%  
**发现时间:** 2025-09-19  
**POC仓库:** [CVE-2024-57366](https://github.com/h4ckusaur/CVE-2024-57366)  

---

### [CVE-2025-49144](CVE-2025-49144-ammarm0010_CVE-2025-49144_PoC.md) 🔴 ✅

**名称:** CVE-2025-49144 Notepad++ 权限提升  
**类型:** 权限提升  
**风险:** 高危，允许低权限用户获得SYSTEM权限  
**投毒风险:** 80%  
**发现时间:** 2025-09-19  
**POC仓库:** [CVE-2025-49144_PoC](https://github.com/ammarm0010/CVE-2025-49144_PoC)  

---

### [CVE-2025-10035](CVE-2025-10035-h4xnz_CVE-2025-10035-Exploit.md) 🔴 

**名称:** CVE-2025-10035-GoAnywhere MFT 远程命令执行  
**类型:** 反序列化漏洞导致的远程命令执行  
**风险:** 高危，可导致服务器被完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-09-19  
**POC仓库:** [CVE-2025-10035-Exploit](https://github.com/h4xnz/CVE-2025-10035-Exploit)  

---

### [CVE-2025-56762](CVE-2025-56762-Shaunak-Chatterjee_CVE-2025-56762.md) 🟡 ✅

**名称:** error.php XSS漏洞  
**类型:** 跨站脚本攻击(XSS)  
**风险:** 中危，可能导致数据窃取、账户劫持和网页篡改  
**投毒风险:** 10%  
**发现时间:** 2025-09-19  
**POC仓库:** [CVE-2025-56762](https://github.com/Shaunak-Chatterjee/CVE-2025-56762)  

---

### [CVE-2025-55241](CVE-2025-55241-Spanky-McSpank_CVE-2025-55241-Internal-Audit.md) 🔴 ✅

**名称:** CVE-2025-55241-Azure Entra 权限提升漏洞  
**类型:** 权限提升  
**风险:** 高危，可能导致全局管理员权限获取，完全控制Entra ID租户  
**投毒风险:** 低，代码库主要为贡献指南和仓库设置说明，未发现恶意代码  
**发现时间:** 2025-09-19  
**POC仓库:** [CVE-2025-55241-Internal-Audit](https://github.com/Spanky-McSpank/CVE-2025-55241-Internal-Audit)  

---

### [CVE-2025-49113](CVE-2025-49113-l4f2s4_CVE-2025-49113-exploit.php.md) 🔴 ✅

**名称:** CVE-2025-49113-Roundcube-Webmail-RCE  
**类型:** PHP对象反序列化导致的远程代码执行  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-09-19  
**POC仓库:** [CVE-2025-49113-exploit.php](https://github.com/l4f2s4/CVE-2025-49113-exploit.php)  

---

### [CVE-2025-22964](CVE-2025-22964-padayali-JD_CVE-2025-22964.md) 🔴 ✅

**名称:** CVE-2025-22964 - DDSN Interactive cm3 Acora CMS SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致未授权访问、数据泄露和数据篡改  
**投毒风险:** 10%  
**发现时间:** 2025-09-19  
**POC仓库:** [CVE-2025-22964](https://github.com/padayali-JD/CVE-2025-22964)  

---

### [CVE-2025-25968](CVE-2025-25968-padayali-JD_CVE-2025-25968.md) 🟡 ✅

**名称:** CVE-2025-25968-DDSN Interactive cm3 Acora CMS-不当访问控制  
**类型:** 不当访问控制  
**风险:** 中危，可能导致敏感信息泄露、账号接管和权限提升  
**投毒风险:** 0%  
**发现时间:** 2025-09-19  
**POC仓库:** [CVE-2025-25968](https://github.com/padayali-JD/CVE-2025-25968)  

---

### [CVE-2025-25967](CVE-2025-25967-padayali-JD_CVE-2025-25967.md) 🟡 ✅

**名称:** CVE-2025-25967-Acora CMS-CSRF  
**类型:** CSRF (跨站请求伪造)  
**风险:** 中危，可能导致账户删除、用户创建等未授权操作  
**投毒风险:** 5%  
**发现时间:** 2025-09-19  
**POC仓库:** [CVE-2025-25967](https://github.com/padayali-JD/CVE-2025-25967)  

---

### [CVE-2025-48799](CVE-2025-48799-mrk336_Header-Havoc-Cracking-CVE-2025-48799-in-Apache-Tomcat.md) 🔴 ✅

**名称:** CVE-2025-48799 Windows Update Service 提权漏洞  
**类型:** 权限提升  
**风险:** 高危，本地权限提升  
**投毒风险:** 10%  
**发现时间:** 2025-09-19  
**POC仓库:** [Header-Havoc-Cracking-CVE-2025-48799-in-Apache-Tomcat](https://github.com/mrk336/Header-Havoc-Cracking-CVE-2025-48799-in-Apache-Tomcat)  

---

### [CVE-2025-59342](CVE-2025-59342-byteReaper77_CVE-2025-59342.md) 🟡 ✅

**名称:** CVE-2025-59342-esm.sh-路径遍历  
**类型:** 路径遍历  
**风险:** 中危，可能导致任意文件写入  
**投毒风险:** 10%  
**发现时间:** 2025-09-18  
**POC仓库:** [CVE-2025-59342](https://github.com/byteReaper77/CVE-2025-59342)  

---

### [CVE-2025-57819](CVE-2025-57819-orange0Mint_CVE-2025-57819_FreePBX.md) 🔴 ✅

**名称:** CVE-2025-57819 - FreePBX Unauthenticated SQL Injection to RCE  
**类型:** SQL Injection, Authentication Bypass, RCE  
**风险:** Critical，未授权远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-09-18  
**POC仓库:** [CVE-2025-57819_FreePBX](https://github.com/orange0Mint/CVE-2025-57819_FreePBX)  

---

### [CVE-2025-33073](CVE-2025-33073-sleepasleepzzz_CVE-2025-33073.md) 🔴 ✅

**名称:** CVE-2025-33073 Windows SMB Client Elevation of Privilege Vulnerability  
**类型:** 特权提升  
**风险:** 高危，允许经过身份验证的攻击者通过网络提升权限  
**投毒风险:** 20%  
**发现时间:** 2025-09-18  
**POC仓库:** [CVE-2025-33073](https://github.com/sleepasleepzzz/CVE-2025-33073)  

---

### [CVE-2023-30258](CVE-2023-30258-AdityaBhatt3010_TryHackMe-Room-Walkthrough-Billing.md) 🔴 ✅

**名称:** CVE-2023-30258 MagnusBilling 命令注入  
**类型:** 命令注入  
**风险:** 高危，允许远程攻击者执行任意命令  
**投毒风险:** 0%  
**发现时间:** 2025-09-18  
**POC仓库:** [TryHackMe-Room-Walkthrough-Billing](https://github.com/AdityaBhatt3010/TryHackMe-Room-Walkthrough-Billing)  

---

### [CVE-2023-30258](CVE-2023-30258-abdullohqurbon0v_CVE-2023-30258-Exploit-For-Magnus-Billing-System.md) 🔴 ✅

**名称:** CVE-2023-30258-MagnusBilling-命令注入  
**类型:** 命令注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-09-18  
**POC仓库:** [CVE-2023-30258-Exploit-For-Magnus-Billing-System](https://github.com/abdullohqurbon0v/CVE-2023-30258-Exploit-For-Magnus-Billing-System)  

---

### [CVE-2023-49367](CVE-2023-49367-barisbaydur_CVE-2023-49367.md) 🔴 ✅

**名称:** CVE-2023-49367 - Kyocera Printer 敏感数据暴露  
**类型:** 敏感数据暴露  
**风险:** 高危，可能导致凭据泄露和未授权访问  
**投毒风险:** 10%  
**发现时间:** 2025-09-18  
**POC仓库:** [CVE-2023-49367](https://github.com/barisbaydur/CVE-2023-49367)  

---

### [CVE-2025-32433](CVE-2025-32433-iteride_CVE-2025-32433.md)  ✅

**名称:** CVE-2025-32433 Erlang/OTP SSH 预认证RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 严重，未经身份验证的远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-09-18  
**POC仓库:** [CVE-2025-32433](https://github.com/iteride/CVE-2025-32433)  

---

### [CVE-2025-53772](CVE-2025-53772-go-bi_CVE-2025-53772-.md) 🔴 

**名称:** CVE-2025-53772-Web Deploy Remote Code Execution  
**类型:** 反序列化漏洞  
**风险:** 高危，远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-09-18  
**POC仓库:** [CVE-2025-53772-](https://github.com/go-bi/CVE-2025-53772-)  

---

### [CVE-2025-43300](CVE-2025-43300-veniversum_cve-2025-43300.md) 🔴 ✅

**名称:** CVE-2025-43300-ImageIO-越界写入  
**类型:** 越界写入  
**风险:** 高危，可能导致内存损坏和任意代码执行  
**投毒风险:** 99%  
**发现时间:** 2025-09-18  
**POC仓库:** [cve-2025-43300](https://github.com/veniversum/cve-2025-43300)  

---

### [CVE-2025-8088](CVE-2025-8088-hbesljx_CVE-2025-8088-EXP.md) 🔴 ✅

**名称:** CVE-2025-8088-WinRAR-路径遍历  
**类型:** 路径遍历  
**风险:** 高危，允许攻击者执行任意代码  
**投毒风险:** 0%  
**发现时间:** 2025-09-18  
**POC仓库:** [CVE-2025-8088-EXP](https://github.com/hbesljx/CVE-2025-8088-EXP)  

---

### [CVE-2019-3396](CVE-2019-3396-HK4zCzi_CVE-2019-3396-Velocity-Server-Side-Template-Injection.md) 🔴 ✅

**名称:** CVE-2019-3396-Confluence Widget Connector Server-Side Template Injection  
**类型:** Server-Side Template Injection (SSTI)  
**风险:** 高危，允许远程攻击者在Confluence服务器或数据中心实例上实现路径遍历和远程代码执行。  
**投毒风险:** 10%  
**发现时间:** 2025-09-18  
**POC仓库:** [CVE-2019-3396-Velocity-Server-Side-Template-Injection](https://github.com/HK4zCzi/CVE-2019-3396-Velocity-Server-Side-Template-Injection)  

---

### [CVE-2025-59359](CVE-2025-59359-mrk336_Cluster-Chaos-Exploiting-CVE-2025-59359-for-Kubernetes-Takeover.md) 🔴 ✅

**名称:** CVE-2025-59359-Chaos-Mesh-OS命令注入  
**类型:** OS命令注入  
**风险:** 高危，允许未经身份验证的集群内攻击者执行远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-09-18  
**POC仓库:** [Cluster-Chaos-Exploiting-CVE-2025-59359-for-Kubernetes-Takeover](https://github.com/mrk336/Cluster-Chaos-Exploiting-CVE-2025-59359-for-Kubernetes-Takeover)  

---

### [CVE-2024-43630](CVE-2024-43630-QuasarBinary_CVE-2024-43630-POC.md) 🔴 ✅

**名称:** CVE-2024-43630 Windows Kernel 权限提升漏洞  
**类型:** 权限提升  
**风险:** 高危，可能导致系统权限提升  
**投毒风险:** 10%  
**发现时间:** 2025-09-17  
**POC仓库:** [CVE-2024-43630-POC](https://github.com/QuasarBinary/CVE-2024-43630-POC)  

---

### [CVE-2024-28397](CVE-2024-28397-vitaciminIPI_CVE-2024-28397-RCE.md) 🔴 ✅

**名称:** CVE-2024-28397-js2py-Sandbox-Escape  
**类型:** 代码注入/沙箱逃逸  
**风险:** 高危，远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-09-17  
**POC仓库:** [CVE-2024-28397-RCE](https://github.com/vitaciminIPI/CVE-2024-28397-RCE)  

---

### [CVE-2020-13777](CVE-2020-13777-shigeki_challenge_CVE-2020-13777.md) 🔴 ✅

**名称:** CVE-2020-13777 GnuTLS Session Ticket 漏洞  
**类型:** 身份验证绕过/信息泄露  
**风险:** 高危，可能导致身份验证绕过和敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-09-17  
**POC仓库:** [challenge_CVE-2020-13777](https://github.com/shigeki/challenge_CVE-2020-13777)  

---

### [CVE-2020-13777](CVE-2020-13777-prprhyt_PoC_TLS1_3_CVE-2020-13777.md) 🔴 ✅

**名称:** CVE-2020-13777-GnuTLS-会话票证加密漏洞  
**类型:** TLS会话票证加密漏洞  
**风险:** 高危，TLS 1.2中可能导致信息泄露，TLS 1.3中可能导致身份验证绕过  
**投毒风险:** 0%  
**发现时间:** 2025-09-17  
**POC仓库:** [PoC_TLS1_3_CVE-2020-13777](https://github.com/prprhyt/PoC_TLS1_3_CVE-2020-13777)  

---

### [CVE-2020-13777](CVE-2020-13777-0xxon_cve-2020-13777.md) 🔴 ✅

**名称:** CVE-2020-13777-GnuTLS会话票证漏洞  
**类型:** 身份验证绕过/信息泄露  
**风险:** 高危，可能导致TLS 1.2中机密性丧失以及TLS 1.3中身份验证绕过  
**投毒风险:** 5%  
**发现时间:** 2025-09-17  
**POC仓库:** [cve-2020-13777](https://github.com/0xxon/cve-2020-13777)  

---

### [CVE-2025-49144](CVE-2025-49144-onniio_CVE-2025-49144.md) 🔴 ✅

**名称:** CVE-2025-49144-Notepad++权限提升  
**类型:** 权限提升  
**风险:** 高危，可能导致完全系统控制  
**投毒风险:** 0%  
**发现时间:** 2025-09-17  
**POC仓库:** [CVE-2025-49144](https://github.com/onniio/CVE-2025-49144)  

---

### [CVE-2025-3248](CVE-2025-3248-wand3rlust_CVE-2025-3248.md) 🔴 ✅

**名称:** CVE-2025-3248-langflow-RCE  
**类型:** 远程代码执行  
**风险:** 高危，未经身份验证的远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-09-17  
**POC仓库:** [CVE-2025-3248](https://github.com/wand3rlust/CVE-2025-3248)  

---

### [CVE-2010-1240](CVE-2010-1240-omarothmann_Embedded-Backdoor-Connection.md) 🔴 ✅

**名称:** CVE-2010-1240 Adobe Reader PDF 嵌入式可执行文件执行漏洞  
**类型:** 文件格式漏洞  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-09-17  
**POC仓库:** [Embedded-Backdoor-Connection](https://github.com/omarothmann/Embedded-Backdoor-Connection)  

---

### [CVE-2025-29927](CVE-2025-29927-adjscent_vulnerable-nextjs-14-CVE-2025-29927.md) 🔴 ✅

**名称:** CVE-2025-29927-Next.js Middleware Authorization Bypass  
**类型:** 授权绕过  
**风险:** 高危，可能导致未授权访问敏感数据和功能  
**投毒风险:** 0%  
**发现时间:** 2025-09-17  
**POC仓库:** [vulnerable-nextjs-14-CVE-2025-29927](https://github.com/adjscent/vulnerable-nextjs-14-CVE-2025-29927)  

---

### [CVE-2010-1240](CVE-2010-1240-Jasmoon99_Embedded-PDF.md) 🔴 ✅

**名称:** CVE-2010-1240 Adobe Reader PDF Embedded Executable Execution  
**类型:** 文件格式漏洞  
**风险:** 高危，允许远程攻击者执行任意本地程序  
**投毒风险:** 10%  
**发现时间:** 2025-09-17  
**POC仓库:** [Embedded-PDF](https://github.com/Jasmoon99/Embedded-PDF)  

---

### [CVE-2010-1240](CVE-2010-1240-asepsaepdin_CVE-2010-1240.md) 🔴 ✅

**名称:** CVE-2010-1240 - Adobe Reader/Acrobat 文件执行漏洞  
**类型:** 文件执行  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-09-17  
**POC仓库:** [CVE-2010-1240](https://github.com/asepsaepdin/CVE-2010-1240)  

---

### [CVE-2010-1240](CVE-2010-1240-12345qwert123456_CVE-2010-1240.md) 🔴 ✅

**名称:** CVE-2010-1240-Adobe Reader Launch File 任意代码执行  
**类型:** 任意代码执行  
**风险:** 高危，可能导致系统完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-09-17  
**POC仓库:** [CVE-2010-1240](https://github.com/12345qwert123456/CVE-2010-1240)  

---

### [CVE-2025-8088](CVE-2025-8088-Shinkirou789_Cve-2025-8088-WinRar-vulnerability.md) 🔴 ✅

**名称:** CVE-2025-8088 WinRAR 路径遍历漏洞  
**类型:** 路径遍历  
**风险:** 高危，可能导致任意代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-09-17  
**POC仓库:** [Cve-2025-8088-WinRar-vulnerability](https://github.com/Shinkirou789/Cve-2025-8088-WinRar-vulnerability)  

---

### [CVE-2024-28397](CVE-2024-28397-nelissandro_CVE-2024-28397-Js2Py-RCE.md) 🔴 ✅

**名称:** CVE-2024-28397-js2py-Sandbox-Escape-RCE  
**类型:** 代码注入/沙箱逃逸  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-09-17  
**POC仓库:** [CVE-2024-28397-Js2Py-RCE](https://github.com/nelissandro/CVE-2024-28397-Js2Py-RCE)  

---

### [CVE-2025-54918](CVE-2025-54918-mrk336_From-Foothold-to-Domain-Admin-Weaponizing-CVE-2025-54918-in-Real-World-DevOps.md) 🔴 ✅

**名称:** CVE-2025-54918 Windows NTLM 提权漏洞  
**类型:** 权限提升  
**风险:** 高危，允许攻击者通过网络提升权限  
**投毒风险:** 10%  
**发现时间:** 2025-09-17  
**POC仓库:** [From-Foothold-to-Domain-Admin-Weaponizing-CVE-2025-54918-in-Real-World-DevOps](https://github.com/mrk336/From-Foothold-to-Domain-Admin-Weaponizing-CVE-2025-54918-in-Real-World-DevOps)  

---

### [CVE-2024-1709](CVE-2024-1709-HussainFathy_CVE-2024-1709.md) 🔴 ✅

**名称:** CVE-2024-1709-ConnectWise ScreenConnect-身份验证绕过  
**类型:** 身份验证绕过  
**风险:** 极高危，可能导致未授权访问、信息泄露和完全系统控制  
**投毒风险:** 10%  
**发现时间:** 2025-09-16  
**POC仓库:** [CVE-2024-1709](https://github.com/HussainFathy/CVE-2024-1709)  

---

### [CVE-2024-1709](CVE-2024-1709-sxyrxyy_CVE-2024-1709-ConnectWise-ScreenConnect-Authentication-Bypass.md) 🔴 ✅

**名称:** CVE-2024-1709-ConnectWise ScreenConnect-Authentication Bypass  
**类型:** Authentication Bypass  
**风险:** 高危，可能导致未经授权访问和控制关键系统  
**投毒风险:** 1%  
**发现时间:** 2025-09-16  
**POC仓库:** [CVE-2024-1709-ConnectWise-ScreenConnect-Authentication-Bypass](https://github.com/sxyrxyy/CVE-2024-1709-ConnectWise-ScreenConnect-Authentication-Bypass)  

---

### [CVE-2024-1709](CVE-2024-1709-cjybao_CVE-2024-1709-and-CVE-2024-1708.md) 🔴 ✅

**名称:** CVE-2024-1709-ConnectWise ScreenConnect-身份验证绕过  
**类型:** 身份验证绕过  
**风险:** 高危，可能导致敏感信息泄露、远程代码执行和控制关键系统  
**投毒风险:** 1%  
**发现时间:** 2025-09-16  
**POC仓库:** [CVE-2024-1709-and-CVE-2024-1708](https://github.com/cjybao/CVE-2024-1709-and-CVE-2024-1708)  

---

### [CVE-2024-1709](CVE-2024-1709-W01fh4cker_ScreenConnect-AuthBypass-RCE.md)  ✅

**名称:** CVE-2024-1709 - ConnectWise ScreenConnect 身份验证绕过与远程代码执行  
**类型:** 身份验证绕过  
**风险:** 严重，可能导致未授权访问、信息泄露和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-09-16  
**POC仓库:** [ScreenConnect-AuthBypass-RCE](https://github.com/W01fh4cker/ScreenConnect-AuthBypass-RCE)  

---

### [CVE-2024-1709](CVE-2024-1709-AMRICHASFUCK_Mass-CVE-2024-1709.md) 🔴 ✅

**名称:** CVE-2024-1709-ConnectWise ScreenConnect-身份验证绕过  
**类型:** 身份验证绕过  
**风险:** 高危，可能导致信息泄露和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-09-16  
**POC仓库:** [Mass-CVE-2024-1709](https://github.com/AMRICHASFUCK/Mass-CVE-2024-1709)  

---

### [CVE-2024-1709](CVE-2024-1709-Teexo_ScreenConnect-CVE-2024-1709-Exploit.md) 🔴 ✅

**名称:** CVE-2024-1709-ConnectWise ScreenConnect-身份验证绕过  
**类型:** 身份验证绕过  
**风险:** 高危，允许未经身份验证的攻击者直接访问敏感信息或关键系统，并可能导致远程代码执行。  
**投毒风险:** 10%  
**发现时间:** 2025-09-16  
**POC仓库:** [ScreenConnect-CVE-2024-1709-Exploit](https://github.com/Teexo/ScreenConnect-CVE-2024-1709-Exploit)  

---

### [CVE-2014-6287](CVE-2014-6287-nika0x38_CVE-2014-6287.md) 🔴 ✅

**名称:** CVE-2014-6287 Rejetto HFS 2.3x 远程命令执行  
**类型:** 远程命令执行  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-09-16  
**POC仓库:** [CVE-2014-6287](https://github.com/nika0x38/CVE-2014-6287)  

---

### [CVE-2024-4157](CVE-2024-4157-Ch4os1_CVE-2024-4157-SSRF-RCE.md) 🔴 ✅

**名称:** CVE-2024-4157 - Contact Form Plugin by Fluent Forms - PHP Object Injection  
**类型:** PHP Object Injection  
**风险:** 高危，可能导致任意文件删除、敏感数据泄露或远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-09-16  
**POC仓库:** [CVE-2024-4157-SSRF-RCE](https://github.com/Ch4os1/CVE-2024-4157-SSRF-RCE)  

---

### [CVE-2025-10533](CVE-2025-10533-h4xnz_CVE-2025-10533-Exploit.md) 🔴 ✅

**名称:** CVE-2025-10533-Mozilla Integer Overflow  
**类型:** 整数溢出  
**风险:** 高危，可能导致任意代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-09-16  
**POC仓库:** [CVE-2025-10533-Exploit](https://github.com/h4xnz/CVE-2025-10533-Exploit)  

---

### [CVE-2025-54106](CVE-2025-54106-callinston_CVE-2025-54106.md) 🔴 

**名称:** CVE-2025-54106-Windows RRAS 远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致完全控制受影响的服务器  
**投毒风险:** 10%  
**发现时间:** 2025-09-16  
**POC仓库:** [CVE-2025-54106](https://github.com/callinston/CVE-2025-54106)  

---

### [CVE-2025-24799](CVE-2025-24799-airbus-cert_CVE-2025-24799-scanner.md) 🔴 ✅

**名称:** CVE-2025-24799-GLPI-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露  
**投毒风险:** 0%  
**发现时间:** 2025-09-16  
**POC仓库:** [CVE-2025-24799-scanner](https://github.com/airbus-cert/CVE-2025-24799-scanner)  

---

### [CVE-2025-27210](CVE-2025-27210-mindeddu_Vulnerable-CVE-2025-27210.md) 🔴 ✅

**名称:** CVE-2025-27210-Node.js-Path Traversal  
**类型:** Path Traversal  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-09-16  
**POC仓库:** [Vulnerable-CVE-2025-27210](https://github.com/mindeddu/Vulnerable-CVE-2025-27210)  

---

### [CVE-2025-50944](CVE-2025-50944-shinyColumn_CVE-2025-50944.md) 🔴 ✅

**名称:** CVE-2025-50944-EagleEyes-证书验证绕过  
**类型:** 证书验证绕过  
**风险:** 高危，可能导致中间人攻击，数据泄露和篡改  
**投毒风险:** 0%  
**发现时间:** 2025-09-16  
**POC仓库:** [CVE-2025-50944](https://github.com/shinyColumn/CVE-2025-50944)  

---

### [CVE-2019-3396](CVE-2019-3396-dothanthitiendiettiende_CVE-2019-3396.md) 🔴 ✅

**名称:** CVE-2019-3396-Atlassian Confluence-服务器端模板注入  
**类型:** 服务器端模板注入 (SSTI)  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-09-16  
**POC仓库:** [CVE-2019-3396](https://github.com/dothanthitiendiettiende/CVE-2019-3396)  

---

### [CVE-2019-3396](CVE-2019-3396-xiaoshuier_CVE-2019-3396.md) 🔴 ✅

**名称:** CVE-2019-3396 - Atlassian Confluence Widget Connector Server-Side Template Injection  
**类型:** Server-Side Template Injection (SSTI)  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-09-16  
**POC仓库:** [CVE-2019-3396](https://github.com/xiaoshuier/CVE-2019-3396)  

---

### [CVE-2019-3396](CVE-2019-3396-pyn3rd_CVE-2019-3396.md) 🔴 ✅

**名称:** CVE-2019-3396 - Atlassian Confluence Widget Connector Server-Side Template Injection  
**类型:** 服务器端模板注入 (Server-Side Template Injection)  
**风险:** 高危，允许远程攻击者在Confluence Server或Data Center实例上实现路径遍历和远程代码执行。  
**投毒风险:** 0%  
**发现时间:** 2025-09-16  
**POC仓库:** [CVE-2019-3396](https://github.com/pyn3rd/CVE-2019-3396)  

---

### [CVE-2019-3396](CVE-2019-3396-quanpt103_CVE-2019-3396.md) 🔴 ✅

**名称:** CVE-2019-3396-Confluence-服务器端模板注入  
**类型:** 服务器端模板注入 (SSTI)  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-09-16  
**POC仓库:** [CVE-2019-3396](https://github.com/quanpt103/CVE-2019-3396)  

---

### [CVE-2019-3396](CVE-2019-3396-vntest11_confluence_CVE-2019-3396.md) 🔴 ✅

**名称:** CVE-2019-3396 - Atlassian Confluence Widget Connector Macro Server-Side Template Injection  
**类型:** 服务器端模板注入 (Server-Side Template Injection)  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-09-16  
**POC仓库:** [confluence_CVE-2019-3396](https://github.com/vntest11/confluence_CVE-2019-3396)  

---

### [CVE-2019-3396](CVE-2019-3396-s1xg0d_CVE-2019-3396.md) 🔴 ✅

**名称:** CVE-2019-3396-Atlassian Confluence-服务器端模板注入  
**类型:** 服务器端模板注入 (SSTI)  
**风险:** 高危，可能导致远程代码执行 (RCE) 和敏感信息泄露  
**投毒风险:** 5%  
**发现时间:** 2025-09-16  
**POC仓库:** [CVE-2019-3396](https://github.com/s1xg0d/CVE-2019-3396)  

---

### [CVE-2019-3396](CVE-2019-3396-tanw923_test1.md) 🔴 ✅

**名称:** CVE-2019-3396-Confluence-RCE  
**类型:** 服务器端模板注入(SSTI)  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-09-16  
**POC仓库:** [test1](https://github.com/tanw923/test1)  

---

### [CVE-2019-3396](CVE-2019-3396-skommando_CVE-2019-3396-confluence-poc.md) 🔴 ✅

**名称:** CVE-2019-3396-Confluence-Server-Side Template Injection  
**类型:** Server-Side Template Injection (SSTI)  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-09-16  
**POC仓库:** [CVE-2019-3396-confluence-poc](https://github.com/skommando/CVE-2019-3396-confluence-poc)  

---

### [CVE-2019-3396](CVE-2019-3396-x-f1v3_CVE-2019-3396.md) 🔴 ✅

**名称:** CVE-2019-3396-Atlassian Confluence Server-服务器端模板注入  
**类型:** 服务器端模板注入 (Server-Side Template Injection)  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-09-16  
**POC仓库:** [CVE-2019-3396](https://github.com/x-f1v3/CVE-2019-3396)  

---

### [CVE-2019-3396](CVE-2019-3396-jas502n_CVE-2019-3396.md) 🔴 ✅

**名称:** CVE-2019-3396 - Atlassian Confluence Widget Connector Server-Side Template Injection  
**类型:** Server-Side Template Injection (SSTI)  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-09-16  
**POC仓库:** [CVE-2019-3396](https://github.com/jas502n/CVE-2019-3396)  

---

### [CVE-2019-3396](CVE-2019-3396-am6539_CVE-2019-3396.md) 🔴 ✅

**名称:** CVE-2019-3396-Confluence-服务器端模板注入  
**类型:** 服务器端模板注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-09-16  
**POC仓库:** [CVE-2019-3396](https://github.com/am6539/CVE-2019-3396)  

---

### [CVE-2019-3396](CVE-2019-3396-W2Ning_CVE-2019-3396.md) 🔴 ✅

**名称:** CVE-2019-3396-Confluence-Widget-Connector-SSTI  
**类型:** 服务器端模板注入(SSTI)  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-09-16  
**POC仓库:** [CVE-2019-3396](https://github.com/W2Ning/CVE-2019-3396)  

---

### [CVE-2019-3396](CVE-2019-3396-JonathanZhou348_CVE-2019-3396TEST.md) 🔴 ✅

**名称:** CVE-2019-3396-Atlassian Confluence-Server-Side Template Injection  
**类型:** Server-Side Template Injection (SSTI)  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-09-16  
**POC仓库:** [CVE-2019-3396TEST](https://github.com/JonathanZhou348/CVE-2019-3396TEST)  

---

### [CVE-2019-3396](CVE-2019-3396-Yt1g3r_CVE-2019-3396_EXP.md) 🔴 ✅

**名称:** CVE-2019-3396 - Atlassian Confluence Widget Connector Macro SSTI RCE  
**类型:** 服务器端模板注入（SSTI）导致远程代码执行（RCE）  
**风险:** 高危，可导致完全控制Confluence服务器  
**投毒风险:** 0%  
**发现时间:** 2025-09-16  
**POC仓库:** [CVE-2019-3396_EXP](https://github.com/Yt1g3r/CVE-2019-3396_EXP)  

---

### [CVE-2019-3396](CVE-2019-3396-yuehanked_cve-2019-3396.md) 🔴 ✅

**名称:** CVE-2019-3396-Atlassian Confluence Widget Connector Macro-SSTI  
**类型:** 服务器端模板注入 (SSTI)  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-09-16  
**POC仓库:** [cve-2019-3396](https://github.com/yuehanked/cve-2019-3396)  

---

### [CVE-2019-3396](CVE-2019-3396-46o60_CVE-2019-3396_Confluence.md) 🔴 ✅

**名称:** CVE-2019-3396_Confluence Widget Connector Macro SSTI  
**类型:** 服务器端模板注入 (SSTI)  
**风险:** 高危，允许远程攻击者实现路径遍历和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-09-16  
**POC仓库:** [CVE-2019-3396_Confluence](https://github.com/46o60/CVE-2019-3396_Confluence)  

---

### [CVE-2019-3396](CVE-2019-3396-PetrusViet_cve-2019-3396.md) 🔴 ✅

**名称:** CVE-2019-3396 - Atlassian Confluence Widget Connector 远程代码执行  
**类型:** 服务器端模板注入 (Server-Side Template Injection)  
**风险:** 高危，允许未授权的远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-09-16  
**POC仓库:** [cve-2019-3396](https://github.com/PetrusViet/cve-2019-3396)  

---

### [CVE-2019-3396](CVE-2019-3396-0xNinjaCyclone_cve-2019-3396.md) 🔴 ✅

**名称:** CVE-2019-3396-Confluence-RCE  
**类型:** 服务器端模板注入 (Server-Side Template Injection)  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-09-16  
**POC仓库:** [cve-2019-3396](https://github.com/0xNinjaCyclone/cve-2019-3396)  

---

### [CVE-2019-3396](CVE-2019-3396-Avento_CVE-2019-3396-Memshell-for-Behinder.md) 🔴 ✅

**名称:** CVE-2019-3396-Atlassian Confluence Widget Connector Server-Side Template Injection  
**类型:** Server-Side Template Injection (SSTI)  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-09-16  
**POC仓库:** [CVE-2019-3396-Memshell-for-Behinder](https://github.com/Avento/CVE-2019-3396-Memshell-for-Behinder)  

---

### [CVE-2019-3396](CVE-2019-3396-kh4sh3i_CVE-2019-3396.md) 🔴 ✅

**名称:** CVE-2019-3396-Confluence-Server-Server-Side Template Injection  
**类型:** Server-Side Template Injection  
**风险:** 高危，允许远程攻击者在Confluence服务器或数据中心实例上实现路径遍历和远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-09-16  
**POC仓库:** [CVE-2019-3396](https://github.com/kh4sh3i/CVE-2019-3396)  

---

### [CVE-2025-8088](CVE-2025-8088-nhattanhh_CVE-2025-8088.md) 🔴 ✅

**名称:** CVE-2025-8088 WinRAR 路径遍历漏洞  
**类型:** 路径遍历  
**风险:** 高危，允许攻击者执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-09-16  
**POC仓库:** [CVE-2025-8088](https://github.com/nhattanhh/CVE-2025-8088)  

---

### [CVE-2025-26686](CVE-2025-26686-mrk336_CVE-2025-26686-The-TCP-IP-Flaw-That-Opens-the-Gates.md) 🔴 ✅

**名称:** CVE-2025-26686 Windows TCP/IP 远程代码执行漏洞  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，攻击者可以通过网络发送特制的数据包，在目标系统上执行任意代码，可能导致系统完全失陷。  
**投毒风险:** 10%  
**发现时间:** 2025-09-16  
**POC仓库:** [CVE-2025-26686-The-TCP-IP-Flaw-That-Opens-the-Gates](https://github.com/mrk336/CVE-2025-26686-The-TCP-IP-Flaw-That-Opens-the-Gates)  

---

### [CVE-2025-3248](CVE-2025-3248-EQSTLab_CVE-2025-3248.md) 🔴 ✅

**名称:** CVE-2025-3248-Langflow-RCE  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 1%  
**发现时间:** 2025-09-16  
**POC仓库:** [CVE-2025-3248](https://github.com/EQSTLab/CVE-2025-3248)  

---

### [CVE-2025-9074](CVE-2025-9074-fortihack_CVE-2025-9074.md) 🔴 ✅

**名称:** CVE-2025-9074 - Docker Desktop 远程API未授权访问  
**类型:** 未授权访问  
**风险:** 高危，可能导致容器逃逸、主机文件系统访问、任意代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-09-15  
**POC仓库:** [CVE-2025-9074](https://github.com/fortihack/CVE-2025-9074)  

---

### [CVE-2017-12611](CVE-2017-12611-brianwrf_S2-053-CVE-2017-12611.md) 🔴 ✅

**名称:** CVE-2017-12611-Apache Struts-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行，控制服务器  
**投毒风险:** 10%  
**发现时间:** 2025-09-15  
**POC仓库:** [S2-053-CVE-2017-12611](https://github.com/brianwrf/S2-053-CVE-2017-12611)  

---

### [CVE-2017-12611](CVE-2017-12611-tcetin704_CVE-2017-12611.md) 🔴 ✅

**名称:** CVE-2017-12611-Apache Struts-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-09-15  
**POC仓库:** [CVE-2017-12611](https://github.com/tcetin704/CVE-2017-12611)  

---

### [CVE-2024-28397](CVE-2024-28397-0xDTC_js2py-Sandbox-Escape-CVE-2024-28397-RCE.md) 🔴 ✅

**名称:** CVE-2024-28397 js2py Sandbox Escape  
**类型:** 代码注入/沙箱逃逸  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-09-15  
**POC仓库:** [js2py-Sandbox-Escape-CVE-2024-28397-RCE](https://github.com/0xDTC/js2py-Sandbox-Escape-CVE-2024-28397-RCE)  

---

### [CVE-2019-9978](CVE-2019-9978-xxoprt_payloadCVE-2019-9978.md) 🟡 ✅

**名称:** CVE-2019-9978-Social-Warfare-Stored-XSS  
**类型:** 存储型跨站脚本 (Stored XSS)  
**风险:** 中危，可能导致用户凭据泄露，网站内容篡改或恶意代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-09-15  
**POC仓库:** [payloadCVE-2019-9978](https://github.com/xxoprt/payloadCVE-2019-9978)  

---

### [CVE-2023-51385](CVE-2023-51385-selecthch_CVE-2023-51385.md) 🔴 ✅

**名称:** CVE-2023-51385-OpenSSH-命令注入  
**类型:** 命令注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-09-15  
**POC仓库:** [CVE-2023-51385](https://github.com/selecthch/CVE-2023-51385)  

---

### [CVE-2025-31161](CVE-2025-31161-acan0007_CVE-2025-31161.md) 🔴 ✅

**名称:** CVE-2025-31161 - CrushFTP身份验证绕过  
**类型:** 身份验证绕过  
**风险:** 高危，可能导致完全系统权限被获取  
**投毒风险:** 0%  
**发现时间:** 2025-09-15  
**POC仓库:** [CVE-2025-31161](https://github.com/acan0007/CVE-2025-31161)  

---

### [CVE-2025-55234](CVE-2025-55234-mrk336_Patch-the-Path-CVE-2025-55234-Detection-Defense.md) 🔴 ✅

**名称:** CVE-2025-55234 Windows SMB Elevation of Privilege Vulnerability  
**类型:** 权限提升  
**风险:** 高危，可能导致域控制权限获取  
**投毒风险:** 5%  
**发现时间:** 2025-09-15  
**POC仓库:** [Patch-the-Path-CVE-2025-55234-Detection-Defense](https://github.com/mrk336/Patch-the-Path-CVE-2025-55234-Detection-Defense)  

---

### [CVE-2024-42009](CVE-2024-42009-Shubhankargupta691_CVE-2024-42009.md) 🔴 ✅

**名称:** CVE-2024-42009-Roundcube-XSS  
**类型:** 跨站脚本 (XSS)  
**风险:** 高危，可能导致信息泄露、会话劫持、恶意代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-09-14  
**POC仓库:** [CVE-2024-42009](https://github.com/Shubhankargupta691/CVE-2024-42009)  

---

### [CVE-2025-12654](CVE-2025-12654-Walekmw_Anydesk-Exploit-CVE-2025-12654-RCE-Builder.md) 🔴 

**名称:** AnyDesk Exploit (基于公开信息综合分析)  
**类型:** RCE, DLL注入, 权限绕过等多种漏洞 (综合分析)  
**风险:** 高危，可能导致远程代码执行、数据泄露、权限提升等  
**投毒风险:** 70%  
**发现时间:** 2025-09-14  
**POC仓库:** [Anydesk-Exploit-CVE-2025-12654-RCE-Builder](https://github.com/Walekmw/Anydesk-Exploit-CVE-2025-12654-RCE-Builder)  

---

### [CVE-2025-24813](CVE-2025-24813-brs6412_CVE-2025-24813.md) 🔴 ✅

**名称:** CVE-2025-24813-Apache Tomcat-Path Equivalence/Deserialization  
**类型:** 路径等价/反序列化  
**风险:** 高危，可能导致信息泄露和远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-09-14  
**POC仓库:** [CVE-2025-24813](https://github.com/brs6412/CVE-2025-24813)  

---

### [CVE-2025-44228](CVE-2025-44228-Waletow_Office-Exploit-Cve2025-Xml-Doc-Docx-Rce-Builder-Fud.md) 🔴 ✅

**名称:** CVE-2025-XXXX - Microsoft Office 远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，允许攻击者在目标系统上执行任意代码  
**投毒风险:** 70%  
**发现时间:** 2025-09-14  
**POC仓库:** [Office-Exploit-Cve2025-Xml-Doc-Docx-Rce-Builder-Fud](https://github.com/Waletow/Office-Exploit-Cve2025-Xml-Doc-Docx-Rce-Builder-Fud)  

---

### [CVE-2025-44228](CVE-2025-44228-Waletow_Lnk-Exploit-FileBinder-Certificate-Spoofer-Reg-Doc-Cve-Rce.md) 🔴 ✅

**名称:** LNK Exploit, File Binder, Certificate Spoofer, Reg Persistence, Document Embedding, CVE Integration, RCE  
**类型:** 多合一漏洞利用工具  
**风险:** 高危，可能导致远程代码执行，系统控制，数据泄露  
**投毒风险:** 70%  
**发现时间:** 2025-09-14  
**POC仓库:** [Lnk-Exploit-FileBinder-Certificate-Spoofer-Reg-Doc-Cve-Rce](https://github.com/Waletow/Lnk-Exploit-FileBinder-Certificate-Spoofer-Reg-Doc-Cve-Rce)  

---

### [CVE-2025-48543](CVE-2025-48543-gamesarchive_CVE-2025-48543.md) 🔴 ✅

**名称:** CVE-2025-48543-Android Runtime Use-After-Free  
**类型:** Use-After-Free  
**风险:** 高危，可导致提权和沙箱逃逸  
**投毒风险:** 10%  
**发现时间:** 2025-09-14  
**POC仓库:** [CVE-2025-48543](https://github.com/gamesarchive/CVE-2025-48543)  

---

### [CVE-2025-21692](CVE-2025-21692-volticks_CVE-2025-21692-poc.md) 🔴 ✅

**名称:** CVE-2025-21692-Linux内核ETS qdisc OOB索引漏洞  
**类型:** 越界读取/写入  
**风险:** 高危，本地权限提升  
**投毒风险:** 10%  
**发现时间:** 2025-09-14  
**POC仓库:** [CVE-2025-21692-poc](https://github.com/volticks/CVE-2025-21692-poc)  

---

### [CVE-2025-57819](CVE-2025-57819-xV4nd3Rx_CVE-2025-57819_FreePBX-PoC.md)  ✅

**名称:** CVE-2025-57819-FreePBX-SQL注入和RCE  
**类型:** SQL注入和RCE  
**风险:** 严重，可能导致完全系统控制和数据泄露  
**投毒风险:** 5%  
**发现时间:** 2025-09-14  
**POC仓库:** [CVE-2025-57819_FreePBX-PoC](https://github.com/xV4nd3Rx/CVE-2025-57819_FreePBX-PoC)  

---

### [CVE-2025-8088](CVE-2025-8088-techcorp_CVE-2025-8088-Exploit.md) 🔴 ✅

**名称:** CVE-2025-8088-WinRAR-路径遍历  
**类型:** 路径遍历  
**风险:** 高危，允许攻击者执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-09-14  
**POC仓库:** [CVE-2025-8088-Exploit](https://github.com/techcorp/CVE-2025-8088-Exploit)  

---

### [CVE-2025-46408](CVE-2025-46408-shinyColumn_CVE-2025-46408.md) 🟡 ✅

**名称:** CVE-2025-46408-EagleEyes Lite Android-不正确的Hostname验证  
**类型:** 不正确的Hostname验证  
**风险:** 中危，可能导致中间人攻击，拦截或篡改敏感数据  
**投毒风险:** 0%  
**发现时间:** 2025-09-13  
**POC仓库:** [CVE-2025-46408](https://github.com/shinyColumn/CVE-2025-46408)  

---

### [CVE-2025-50110](CVE-2025-50110-shinyColumn_CVE-2025-50110.md) 🔴 ✅

**名称:** CVE-2025-50110 - EagleEyes Lite Cleartext Transmission of Sensitive Information  
**类型:** 敏感信息泄露  
**风险:** 高危，可能导致账户凭据泄露和未授权访问CCTV系统  
**投毒风险:** 0%  
**发现时间:** 2025-09-13  
**POC仓库:** [CVE-2025-50110](https://github.com/shinyColumn/CVE-2025-50110)  

---

### [CVE-2025-8088](CVE-2025-8088-tartalu_CVE-2025-8088.md) 🔴 ✅

**名称:** CVE-2025-8088-WinRAR-路径遍历  
**类型:** 路径遍历  
**风险:** 高危，可能导致任意代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-09-13  
**POC仓库:** [CVE-2025-8088](https://github.com/tartalu/CVE-2025-8088)  

---

### [CVE-2025-53770](CVE-2025-53770-go-bi_sharepoint-CVE-2025-53770.md) 🔴 ✅

**名称:** CVE-2025-53770 - Microsoft SharePoint Server 远程代码执行漏洞  
**类型:** 反序列化漏洞导致远程代码执行  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-09-13  
**POC仓库:** [sharepoint-CVE-2025-53770](https://github.com/go-bi/sharepoint-CVE-2025-53770)  

---

### [CVE-2025-2945](CVE-2025-2945-Cycloctane_cve-2025-2945-poc.md) 🔴 ✅

**名称:** CVE-2025-2945-pgAdmin 4-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，允许经过身份验证的用户执行任意代码。  
**投毒风险:** 10%  
**发现时间:** 2025-09-13  
**POC仓库:** [cve-2025-2945-poc](https://github.com/Cycloctane/cve-2025-2945-poc)  

---

### [CVE-2025-54309](CVE-2025-54309-chin-tech_CrushFTP_CVE-2025-54309.md) 🔴 ✅

**名称:** CVE-2025-54309 - CrushFTP AS2 Validation Authentication Bypass  
**类型:** 身份验证绕过  
**风险:** 高危，允许未经授权的远程攻击者获得管理员访问权限  
**投毒风险:** 0%  
**发现时间:** 2025-09-13  
**POC仓库:** [CrushFTP_CVE-2025-54309](https://github.com/chin-tech/CrushFTP_CVE-2025-54309)  

---

### [CVE-2025-56019](CVE-2025-56019-Yashodhanvivek_Agatsa-EasyTouch-Plus---CVE-2025-56019.md) 🔴 

**名称:** CVE-2025-6019  
**类型:** 本地权限提升 (LPE)  
**风险:** 高危，允许本地用户提升至root权限  
**投毒风险:** 0%  
**发现时间:** 2025-09-13  
**POC仓库:** [Agatsa-EasyTouch-Plus---CVE-2025-56019](https://github.com/Yashodhanvivek/Agatsa-EasyTouch-Plus---CVE-2025-56019)  

---

### [CVE-2025-9776](CVE-2025-9776-SnailSploit_CVE-2025-9776.md) 🟡 ✅

**名称:** CVE-2025-9776 — CatFolders WordPress Plugin: Authenticated SQL Injection via CSV Import  
**类型:** SQL注入  
**风险:** 中危，可能导致数据泄露和数据操纵  
**投毒风险:** 10%  
**发现时间:** 2025-09-13  
**POC仓库:** [CVE-2025-9776](https://github.com/SnailSploit/CVE-2025-9776)  

---

### [CVE-2025-48384](CVE-2025-48384-s41r4j_CVE-2025-48384.md) 🔴 ✅

**名称:** CVE-2025-48384-Git-任意代码执行  
**类型:** 任意代码执行  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-09-13  
**POC仓库:** [CVE-2025-48384](https://github.com/s41r4j/CVE-2025-48384)  

---

### [CVE-2025-48384](CVE-2025-48384-s41r4j_CVE-2025-48384-submodule.md) 🔴 ✅

**名称:** CVE-2025-48384-Git允许通过损坏的配置引用执行任意代码  
**类型:** 任意代码执行  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-09-13  
**POC仓库:** [CVE-2025-48384-submodule](https://github.com/s41r4j/CVE-2025-48384-submodule)  

---

### [CVE-2025-3639](CVE-2025-3639-6lj_CVE-2025-3639.md)  ✅

**名称:** CVE-2025-3639-Liferay Portal/DXP 登录绕过  
**类型:** 身份验证绕过  
**风险:** 低危  
**投毒风险:** 10%  
**发现时间:** 2025-09-13  
**POC仓库:** [CVE-2025-3639](https://github.com/6lj/CVE-2025-3639)  

---

### [CVE-2022-30190](CVE-2022-30190-Imeneallouche_Follina-attack-CVE-2022-30190-.md) 🔴 ✅

**名称:** CVE-2022-30190-Follina-MSDT远程代码执行漏洞  
**类型:** 远程代码执行  
**风险:** 高危，可导致远程代码执行，控制受害者系统  
**投毒风险:** 10%  
**发现时间:** 2025-09-13  
**POC仓库:** [Follina-attack-CVE-2022-30190-](https://github.com/Imeneallouche/Follina-attack-CVE-2022-30190-)  

---

### [CVE-2025-55234](CVE-2025-55234-mrk336_CVE-2025-55234.md) 🔴 ✅

**名称:** CVE-2025-55234 Windows SMB Elevation of Privilege Vulnerability  
**类型:** 权限提升  
**风险:** 高危，允许攻击者进行中继攻击并提升权限  
**投毒风险:** 10%  
**发现时间:** 2025-09-13  
**POC仓库:** [CVE-2025-55234](https://github.com/mrk336/CVE-2025-55234)  

---

### [CVE-2024-4577](CVE-2024-4577-PhinehasNarh_CVE-2024-4577-LetsDefend-walkthrough.md) 🔴 ✅

**名称:** CVE-2024-4577 PHP-CGI 参数注入  
**类型:** 远程代码执行  
**风险:** 高危，允许未经身份验证的攻击者在受影响的 PHP 服务器上执行任意代码。  
**投毒风险:** 5%  
**发现时间:** 2025-09-13  
**POC仓库:** [CVE-2024-4577-LetsDefend-walkthrough](https://github.com/PhinehasNarh/CVE-2024-4577-LetsDefend-walkthrough)  

---

### [CVE-2022-30190](CVE-2022-30190-ErrorNoInternet_FollinaScanner.md) 🔴 ✅

**名称:** CVE-2022-30190 - Microsoft MSDT Follina 远程代码执行漏洞  
**类型:** 远程代码执行  
**风险:** 高危，可导致远程代码执行，完全控制受害者系统  
**投毒风险:** 1%  
**发现时间:** 2025-09-13  
**POC仓库:** [FollinaScanner](https://github.com/ErrorNoInternet/FollinaScanner)  

---

### [CVE-2022-30190](CVE-2022-30190-Malwareman007_Deathnote.md) 🔴 ✅

**名称:** CVE-2022-30190-Microsoft Windows MSDT 远程代码执行漏洞 (Follina)  
**类型:** 远程代码执行  
**风险:** 高危，允许攻击者以调用应用程序的权限执行任意代码，可能导致系统完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-09-13  
**POC仓库:** [Deathnote](https://github.com/Malwareman007/Deathnote)  

---

### [CVE-2024-4577](CVE-2024-4577-watchtowrlabs_CVE-2024-4577.md)  ✅

**名称:** CVE-2024-4577-PHP-CGI Argument Injection  
**类型:** 远程代码执行(RCE)  
**风险:** 严重，可导致远程代码执行，服务器完全控制  
**投毒风险:** 5%  
**发现时间:** 2025-09-13  
**POC仓库:** [CVE-2024-4577](https://github.com/watchtowrlabs/CVE-2024-4577)  

---

### [CVE-2024-4577](CVE-2024-4577-huseyinstif_CVE-2024-4577-Nuclei-Template.md) 🔴 ✅

**名称:** CVE-2024-4577 PHP CGI Argument Injection  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 5%  
**发现时间:** 2025-09-13  
**POC仓库:** [CVE-2024-4577-Nuclei-Template](https://github.com/huseyinstif/CVE-2024-4577-Nuclei-Template)  

---

### [CVE-2024-4577](CVE-2024-4577-mananjain61_PHP-CGI-INTERNAL-RCE.md)  ✅

**名称:** CVE-2024-4577 PHP-CGI 参数注入导致 RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 严重，未经身份验证的攻击者可以在受影响的服务器上执行任意代码。  
**投毒风险:** 10%  
**发现时间:** 2025-09-12  
**POC仓库:** [PHP-CGI-INTERNAL-RCE](https://github.com/mananjain61/PHP-CGI-INTERNAL-RCE)  

---

### [CVE-2022-0847](CVE-2022-0847-orsuprasad_CVE-2022-0847-DirtyPipe-Exploits.md) 🔴 ✅

**名称:** CVE-2022-0847-Dirty Pipe  
**类型:** 本地权限提升  
**风险:** 高危，允许本地用户修改只读文件并提升权限  
**投毒风险:** 10%  
**发现时间:** 2025-09-12  
**POC仓库:** [CVE-2022-0847-DirtyPipe-Exploits](https://github.com/orsuprasad/CVE-2022-0847-DirtyPipe-Exploits)  

---

### [CVE-2025-48384](CVE-2025-48384-airkewld_cve-2025-48384-submodule.md) 🔴 ✅

**名称:** CVE-2025-48384-Git配置注入与RCE  
**类型:** 配置注入/远程代码执行  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-09-12  
**POC仓库:** [cve-2025-48384-submodule](https://github.com/airkewld/cve-2025-48384-submodule)  

---

### [CVE-2022-25765](CVE-2022-25765-PurpleWaveIO_CVE-2022-25765-pdfkit-Exploit-Reverse-Shell.md) 🔴 ✅

**名称:** CVE-2022-25765-pdfkit-命令注入  
**类型:** 命令注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-09-12  
**POC仓库:** [CVE-2022-25765-pdfkit-Exploit-Reverse-Shell](https://github.com/PurpleWaveIO/CVE-2022-25765-pdfkit-Exploit-Reverse-Shell)  

---

### [CVE-2025-57819](CVE-2025-57819-watchtowrlabs_watchTowr-vs-FreePBX-CVE-2025-57819.md)  ✅

**名称:** CVE-2025-57819-FreePBX-身份验证绕过与SQL注入导致RCE  
**类型:** 身份验证绕过 + SQL注入 + RCE  
**风险:** 严重，未经身份验证的攻击者可以执行任意数据库操作和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-09-12  
**POC仓库:** [watchTowr-vs-FreePBX-CVE-2025-57819](https://github.com/watchtowrlabs/watchTowr-vs-FreePBX-CVE-2025-57819)  

---

### [CVE-2025-57819](CVE-2025-57819-MuhammadWaseem29_SQL-Injection-and-RCE_CVE-2025-57819.md)  ✅

**名称:** CVE-2025-57819-FreePBX-Authentication Bypass leading to SQL Injection and RCE  
**类型:** Authentication Bypass, SQL Injection, Remote Code Execution  
**风险:** 严重，未授权远程代码执行，可能导致完全系统控制  
**投毒风险:** 5%  
**发现时间:** 2025-09-12  
**POC仓库:** [SQL-Injection-and-RCE_CVE-2025-57819](https://github.com/MuhammadWaseem29/SQL-Injection-and-RCE_CVE-2025-57819)  

---

### [CVE-2025-54914](CVE-2025-54914-Ash1996x_CVE-2025-54914-PoC.md) 🔴 

**名称:** CVE-2025-54914 Azure Networking Elevation of Privilege Vulnerability  
**类型:** Elevation of Privilege  
**风险:** Critical, Potential for complete compromise of Azure Network resources.  
**投毒风险:** 10%  
**发现时间:** 2025-09-12  
**POC仓库:** [CVE-2025-54914-PoC](https://github.com/Ash1996x/CVE-2025-54914-PoC)  

---

### [CVE-2022-25765](CVE-2022-25765-Wai-Yan-Kyaw_PDFKitExploit.md) 🔴 ✅

**名称:** CVE-2022-25765-pdfkit-命令注入  
**类型:** 命令注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-09-12  
**POC仓库:** [PDFKitExploit](https://github.com/Wai-Yan-Kyaw/PDFKitExploit)  

---

### [CVE-2022-25765](CVE-2022-25765-LordRNA_CVE-2022-25765.md) 🔴 ✅

**名称:** CVE-2022-25765-pdfkit-命令注入  
**类型:** 命令注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-09-12  
**POC仓库:** [CVE-2022-25765](https://github.com/LordRNA/CVE-2022-25765)  

---

### [CVE-2022-25765](CVE-2022-25765-shamo0_PDFkit-CMD-Injection.md) 🔴 ✅

**名称:** CVE-2022-25765-pdfkit-命令注入  
**类型:** 命令注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-09-12  
**POC仓库:** [PDFkit-CMD-Injection](https://github.com/shamo0/PDFkit-CMD-Injection)  

---

### [CVE-2022-25765](CVE-2022-25765-nikn0laty_PDFkit-CMD-Injection-CVE-2022-25765.md) 🔴 ✅

**名称:** CVE-2022-25765-pdfkit-命令注入  
**类型:** 命令注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-09-12  
**POC仓库:** [PDFkit-CMD-Injection-CVE-2022-25765](https://github.com/nikn0laty/PDFkit-CMD-Injection-CVE-2022-25765)  

---

### [CVE-2022-25765](CVE-2022-25765-lekosbelas_PDFkit-CMD-Injection.md) 🔴 ✅

**名称:** CVE-2022-25765-pdfkit-命令注入  
**类型:** 命令注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-09-12  
**POC仓库:** [PDFkit-CMD-Injection](https://github.com/lekosbelas/PDFkit-CMD-Injection)  

---

### [CVE-2022-25765](CVE-2022-25765-lowercasenumbers_CVE-2022-25765.md) 🔴 ✅

**名称:** CVE-2022-25765-pdfkit-命令注入  
**类型:** 命令注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-09-12  
**POC仓库:** [CVE-2022-25765](https://github.com/lowercasenumbers/CVE-2022-25765)  

---

### [CVE-2022-25765](CVE-2022-25765-UNICORDev_exploit-CVE-2022-25765.md) 🔴 ✅

**名称:** CVE-2022-25765-pdfkit-命令注入  
**类型:** 命令注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-09-12  
**POC仓库:** [exploit-CVE-2022-25765](https://github.com/UNICORDev/exploit-CVE-2022-25765)  

---

### [CVE-2025-8571](CVE-2025-8571-chimdi2700_CVE-2025-8571.md) 🟡 

**名称:** CVE-2025-8571-ConcreteCMS-Reflected XSS  
**类型:** Reflected XSS  
**风险:** 中危，可能导致会话劫持、网页内容篡改、恶意重定向和管理员权限下的未授权操作  
**投毒风险:** 0%  
**发现时间:** 2025-09-12  
**POC仓库:** [CVE-2025-8571](https://github.com/chimdi2700/CVE-2025-8571)  

---

### [CVE-2025-51006](CVE-2025-51006-sy460129_CVE-2025-51006.md) 🟡 ✅

**名称:** CVE-2025-51006-tcpreplay-double-free  
**类型:** Double Free  
**风险:** 中危，可能导致拒绝服务(DoS)  
**投毒风险:** 10%  
**发现时间:** 2025-09-12  
**POC仓库:** [CVE-2025-51006](https://github.com/sy460129/CVE-2025-51006)  

---

### [CVE-2025-21333](CVE-2025-21333-rahul0xkr_Reproducing-CVE-2025-21333-.md) 🔴 ✅

**名称:** CVE-2025-21333-Windows Hyper-V NT Kernel Integration VSP Elevation of Privilege Vulnerability  
**类型:** 权限提升  
**风险:** 高危，可导致虚拟机权限提升  
**投毒风险:** 10%  
**发现时间:** 2025-09-12  
**POC仓库:** [Reproducing-CVE-2025-21333-](https://github.com/rahul0xkr/Reproducing-CVE-2025-21333-)  

---

### [CVE-2025-21333](CVE-2025-21333-rahul0xkr_Hyper-V-CVE-2025-21333-Analysis.md) 🔴 ✅

**名称:** CVE-2025-21333-Windows Hyper-V NT Kernel Integration VSP Elevation of Privilege Vulnerability  
**类型:** Windows Hyper-V NT Kernel Integration VSP Elevation of Privilege  
**风险:** 高危，可能导致权限提升  
**投毒风险:** 5%  
**发现时间:** 2025-09-12  
**POC仓库:** [Hyper-V-CVE-2025-21333-Analysis](https://github.com/rahul0xkr/Hyper-V-CVE-2025-21333-Analysis)  

---

### [CVE-2023-52927](CVE-2023-52927-HoangNhoo_Reproduce-CVE-2023-52927.md) 🟡 

**名称:** CVE-2023-52927-Linux Kernel Netfilter Expectation Handling  
**类型:** 逻辑错误/拒绝服务  
**风险:** 中危，可能导致拒绝服务  
**投毒风险:** 0%  
**发现时间:** 2025-09-12  
**POC仓库:** [Reproduce-CVE-2023-52927](https://github.com/HoangNhoo/Reproduce-CVE-2023-52927)  

---

### [CVE-2025-4123](CVE-2025-4123-ItsNee_Grafana-CVE-2025-4123-POC.md) 🔴 ✅

**名称:** CVE-2025-4123-Grafana-XSS和SSRF  
**类型:** 跨站脚本 (XSS) 和服务器端请求伪造 (SSRF)  
**风险:** 高危，可能导致账户接管、敏感信息泄露、远程代码执行（通过SSRF）  
**投毒风险:** 1%  
**发现时间:** 2025-09-12  
**POC仓库:** [Grafana-CVE-2025-4123-POC](https://github.com/ItsNee/Grafana-CVE-2025-4123-POC)  

---

### [CVE-2024-4701](CVE-2024-4701-JoeBeeton_CVE-2024-4701-POC.md) 🔴 ✅

**名称:** CVE-2024-4701-Netflix Genie-路径遍历导致远程代码执行  
**类型:** 路径遍历  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-09-12  
**POC仓库:** [CVE-2024-4701-POC](https://github.com/JoeBeeton/CVE-2024-4701-POC)  

---

### [CVE-2024-4701](CVE-2024-4701-JinhyukKo_CVE-2024-4701-POC.md) 🔴 ✅

**名称:** CVE-2024-4701-Netflix Genie-路径遍历导致远程代码执行  
**类型:** 路径遍历  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-09-12  
**POC仓库:** [CVE-2024-4701-POC](https://github.com/JinhyukKo/CVE-2024-4701-POC)  

---

### [CVE-2025-3248](CVE-2025-3248-min8282_CVE-2025-3248.md) 🔴 ✅

**名称:** CVE-2025-3248-Langflow-代码注入  
**类型:** 代码注入  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 20%  
**发现时间:** 2025-09-12  
**POC仓库:** [CVE-2025-3248](https://github.com/min8282/CVE-2025-3248)  

---

### [CVE-2024-3094](CVE-2024-3094-mrk336_CVE-2024-3094.md)  ✅

**名称:** CVE-2024-3094 XZ Utils Backdoor  
**类型:** 供应链攻击/后门  
**风险:** 极危，允许未经授权的远程访问和代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-09-12  
**POC仓库:** [CVE-2024-3094](https://github.com/mrk336/CVE-2024-3094)  

---

### [CVE-2025-29927](CVE-2025-29927-MKIRAHMET_CVE-2025-29927-PoC.md) 🔴 ✅

**名称:** CVE-2025-29927-Next.js-Authorization Bypass  
**类型:** 权限绕过  
**风险:** 高危，可能导致未授权访问和数据泄露  
**投毒风险:** 5%  
**发现时间:** 2025-09-11  
**POC仓库:** [CVE-2025-29927-PoC](https://github.com/MKIRAHMET/CVE-2025-29927-PoC)  

---

### [CVE-2025-55891](CVE-2025-55891-terribledactyl_CVE-2025-55891.md) 🔴 ✅

**名称:** CVE-2025-55891: docuPrinter Pro TIFFCP.EXE 堆损坏漏洞  
**类型:** 堆损坏  
**风险:** 高危，可能导致任意代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-09-11  
**POC仓库:** [CVE-2025-55891](https://github.com/terribledactyl/CVE-2025-55891)  

---

### [CVE-2022-0847](CVE-2022-0847-Shadow-Spinner_CVE-2022-0847.md) 🔴 ✅

**名称:** CVE-2022-0847  
**类型:** 本地权限提升  
**风险:** 高危，允许本地用户提升权限至 root  
**投毒风险:** 5%  
**发现时间:** 2025-09-11  
**POC仓库:** [CVE-2022-0847](https://github.com/Shadow-Spinner/CVE-2022-0847)  

---

### [CVE-2019-18935](CVE-2019-18935-quyt0_CVE-2019-18935-exploit-study.md) 🔴 ✅

**名称:** CVE-2019-18935-Telerik UI for ASP.NET AJAX-反序列化RCE  
**类型:** 反序列化远程代码执行  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-09-11  
**POC仓库:** [CVE-2019-18935-exploit-study](https://github.com/quyt0/CVE-2019-18935-exploit-study)  

---

### [CVE-2025-8570](CVE-2025-8570-Nxploited_CVE-2025-8570.md)  ✅

**名称:** CVE-2025-8570 - BeyondCart Connector 权限提升  
**类型:** 权限提升  
**风险:** 严重，可能导致未授权访问和控制WordPress站点  
**投毒风险:** 0%  
**发现时间:** 2025-09-11  
**POC仓库:** [CVE-2025-8570](https://github.com/Nxploited/CVE-2025-8570)  

---

### [CVE-2025-42944](CVE-2025-42944-rxerium_CVE-2025-42944.md) 🔴 ✅

**名称:** CVE-2025-42944 SAP NetWeaver RMI-P4反序列化漏洞  
**类型:** 反序列化  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-09-11  
**POC仓库:** [CVE-2025-42944](https://github.com/rxerium/CVE-2025-42944)  

---

### [CVE-2018-6574](CVE-2018-6574-currently-unkwn_CVE-2018-6574.md) 🔴 ✅

**名称:** CVE-2018-6574-Golang go get RCE  
**类型:** 远程代码执行  
**风险:** 高危，允许攻击者在受害者机器上执行任意命令  
**投毒风险:** 20%  
**发现时间:** 2025-09-11  
**POC仓库:** [CVE-2018-6574](https://github.com/currently-unkwn/CVE-2018-6574)  

---

### [CVE-2025-31258](CVE-2025-31258-sureshkumarsat_CVE-2025-31258-PoC.md) 🔴 ✅

**名称:** CVE-2025-31258-macOS-沙箱逃逸  
**类型:** 沙箱逃逸  
**风险:** 高危，允许应用程序突破其沙箱限制  
**投毒风险:** 95%  
**发现时间:** 2025-09-11  
**POC仓库:** [CVE-2025-31258-PoC](https://github.com/sureshkumarsat/CVE-2025-31258-PoC)  

---

### [CVE-2018-6574](CVE-2018-6574-adendarys_CVE-2018-6574.md) 🔴 ✅

**名称:** CVE-2018-6574-Go-get远程命令执行  
**类型:** 远程命令执行  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-09-11  
**POC仓库:** [CVE-2018-6574](https://github.com/adendarys/CVE-2018-6574)  

---

### [CVE-2024-32019](CVE-2024-32019-T1erno_CVE-2024-32019-Netdata-ndsudo-Privilege-Escalation-PoC.md) 🔴 ✅

**名称:** CVE-2024-32019-Netdata-本地提权  
**类型:** 本地提权  
**风险:** 高危，允许低权限用户通过PATH劫持执行任意代码  
**投毒风险:** 0%  
**发现时间:** 2025-09-11  
**POC仓库:** [CVE-2024-32019-Netdata-ndsudo-Privilege-Escalation-PoC](https://github.com/T1erno/CVE-2024-32019-Netdata-ndsudo-Privilege-Escalation-PoC)  

---

### [CVE-2021-21239](CVE-2021-21239-RyanBoomer30_CVE-2021-21239-Exploit.md) 🟡 ✅

**名称:** CVE-2021-21239-pysaml2-签名绕过  
**类型:** 签名绕过  
**风险:** 中危，可能导致身份伪造和权限提升  
**投毒风险:** 2%  
**发现时间:** 2025-09-10  
**POC仓库:** [CVE-2021-21239-Exploit](https://github.com/RyanBoomer30/CVE-2021-21239-Exploit)  

---

### [CVE-2021-21239](CVE-2021-21239-GrantBirki_redash-vulnerable.md) 🟡 ✅

**名称:** CVE-2021-21239-pysaml2-签名绕过  
**类型:** 签名绕过  
**风险:** 中危，可能导致身份认证绕过，进而未授权访问  
**投毒风险:** 10%  
**发现时间:** 2025-09-10  
**POC仓库:** [redash-vulnerable](https://github.com/GrantBirki/redash-vulnerable)  

---

### [CVE-2021-21239](CVE-2021-21239-illera88_CVE-2021-21239.md) 🔴 ✅

**名称:** CVE-2021-21239-pysaml2-签名绕过  
**类型:** 签名绕过  
**风险:** 高危，可能导致用户伪造和权限提升  
**投毒风险:** 10%  
**发现时间:** 2025-09-10  
**POC仓库:** [CVE-2021-21239](https://github.com/illera88/CVE-2021-21239)  

---

### [CVE-2025-24893](CVE-2025-24893-Bishben_xwiki-15.10.8-reverse-shell-cve-2025-24893.md)  ✅

**名称:** CVE-2025-24893-XWiki-远程代码执行  
**类型:** 远程代码执行  
**风险:** 严重，可能导致完全控制受影响的系统  
**投毒风险:** 10%  
**发现时间:** 2025-09-10  
**POC仓库:** [xwiki-15.10.8-reverse-shell-cve-2025-24893](https://github.com/Bishben/xwiki-15.10.8-reverse-shell-cve-2025-24893)  

---

### [CVE-2025-55232](CVE-2025-55232-h4xnz_CVE-2025-55232-Exploit.md)  ✅

**名称:** CVE-2025-55232 - Microsoft HPC Pack 远程代码执行漏洞  
**类型:** 反序列化漏洞  
**风险:** 严重，可能导致远程代码执行和完全系统控制  
**投毒风险:** 80%  
**发现时间:** 2025-09-10  
**POC仓库:** [CVE-2025-55232-Exploit](https://github.com/h4xnz/CVE-2025-55232-Exploit)  

---

### [CVE-2025-24054](CVE-2025-24054-yum1ra_CVE-2025-24054_CVE-2025-24071-PoC.md) 🟡 ✅

**名称:** CVE-2025-24054 - NTLM Hash Disclosure Spoofing  
**类型:** NTLM Hash Disclosure Spoofing  
**风险:** 中危，可能导致凭据泄露和身份冒充  
**投毒风险:** 5%  
**发现时间:** 2025-09-10  
**POC仓库:** [CVE-2025-24054_CVE-2025-24071-PoC](https://github.com/yum1ra/CVE-2025-24054_CVE-2025-24071-PoC)  

---

### [CVE-2025-42957](CVE-2025-42957-mrk336_CVE-2025-42957-SAP-S-4HANA-Under-Siege.md)  ✅

**名称:** CVE-2025-42957-SAP S/4HANA-ABAP代码注入  
**类型:** ABAP代码注入  
**风险:** 严重，可能导致完全系统控制，数据泄露，业务流程篡改，拒绝服务  
**投毒风险:** 10%  
**发现时间:** 2025-09-10  
**POC仓库:** [CVE-2025-42957-SAP-S-4HANA-Under-Siege](https://github.com/mrk336/CVE-2025-42957-SAP-S-4HANA-Under-Siege)  

---

### [CVE-2025-49113](CVE-2025-49113-Zuack55_Roundcube-1.6.10-Post-Auth-RCE-CVE-2025-49113-.md) 🔴 ✅

**名称:** CVE-2025-49113-Roundcube-PHP对象反序列化  
**类型:** PHP对象反序列化  
**风险:** 高危，可远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-09-10  
**POC仓库:** [Roundcube-1.6.10-Post-Auth-RCE-CVE-2025-49113-](https://github.com/Zuack55/Roundcube-1.6.10-Post-Auth-RCE-CVE-2025-49113-)  

---

### [CVE-2025-56605](CVE-2025-56605-Userr404_CVE-2025-56605.md) 🟡 ✅

**名称:** CVE-2025-56605 - Event Management System - Reflected XSS  
**类型:** Reflected XSS  
**风险:** 中危，可能导致用户信息泄露或会话劫持  
**投毒风险:** 10%  
**发现时间:** 2025-09-10  
**POC仓库:** [CVE-2025-56605](https://github.com/Userr404/CVE-2025-56605)  

---

### [CVE-2025-32433](CVE-2025-32433-scandijamjam1_CVE-2025-32433.md) 🔴 ✅

**名称:** CVE-2025-32433-Erlang/OTP SSH Pre-Authentication RCE  
**类型:** 远程代码执行(RCE)  
**风险:** 高危，未经身份验证即可执行远程代码  
**投毒风险:** 5%  
**发现时间:** 2025-09-10  
**POC仓库:** [CVE-2025-32433](https://github.com/scandijamjam1/CVE-2025-32433)  

---

### [CVE-2025-57520](CVE-2025-57520-onurcangnc_CVE-2025-57520-Stored-XSS-in-Decap-CMS-3.8.3-.md) 🔴 ✅

**名称:** CVE-2025-57520 – Stored XSS in Decap CMS (<= 3.8.3)  
**类型:** Stored Cross-Site Scripting (XSS)  
**风险:** 高危，可能导致会话劫持、凭据盗窃、任意JavaScript执行，进而导致内容篡改和后门注入  
**投毒风险:** 10%  
**发现时间:** 2025-09-10  
**POC仓库:** [CVE-2025-57520-Stored-XSS-in-Decap-CMS-3.8.3-](https://github.com/onurcangnc/CVE-2025-57520-Stored-XSS-in-Decap-CMS-3.8.3-)  

---

### [CVE-2025-31161](CVE-2025-31161-f4dee-backup_CVE-2025-31161.md) 🔴 ✅

**名称:** CVE-2025-31161-CrushFTP-身份验证绕过  
**类型:** 身份验证绕过  
**风险:** 高危，可能导致完全控制系统  
**投毒风险:** 1%  
**发现时间:** 2025-09-10  
**POC仓库:** [CVE-2025-31161](https://github.com/f4dee-backup/CVE-2025-31161)  

---

### [CVE-2025-57392](CVE-2025-57392-meisterlos_CVE-2025-57392.md) 🔴 ✅

**名称:** CVE-2025-57392-BenimPOS-Insecure File Permissions  
**类型:** Insecure File Permissions  
**风险:** 高危，可能导致权限提升和恶意代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-09-09  
**POC仓库:** [CVE-2025-57392](https://github.com/meisterlos/CVE-2025-57392)  

---

### [CVE-2025-5095](CVE-2025-5095-TeteuXD2_CVE-2025-5095-POC.md) 🔴 

**名称:** CVE-2025-5095-Burk Technology ARC Solo-未授权密码更改  
**类型:** 未授权访问  
**风险:** 高危，允许未授权的攻击者完全控制设备  
**投毒风险:** 95%  
**发现时间:** 2025-09-09  
**POC仓库:** [CVE-2025-5095-POC](https://github.com/TeteuXD2/CVE-2025-5095-POC)  

---

### [CVE-2025-32434](CVE-2025-32434-2h3ph3rd_CVE-2025-32434.md)  ✅

**名称:** CVE-2025-32434-PyTorch-反序列化RCE  
**类型:** 反序列化RCE  
**风险:** 严重，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-09-09  
**POC仓库:** [CVE-2025-32434](https://github.com/2h3ph3rd/CVE-2025-32434)  

---

### [CVE-2025-43300](CVE-2025-43300-PwnToday_CVE-2025-43300.md) 🔴 ✅

**名称:** CVE-2025-43300-iOS/macOS DNG Image Processing Memory Corruption  
**类型:** 内存损坏  
**风险:** 高危，可能导致内存损坏、崩溃或潜在的代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-09-09  
**POC仓库:** [CVE-2025-43300](https://github.com/PwnToday/CVE-2025-43300)  

---

### [CVE-2018-11776](CVE-2018-11776-hook-s3c_CVE-2018-11776-Python-PoC.md) 🔴 ✅

**名称:** CVE-2018-11776 Apache Struts 远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，允许未经身份验证的远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-09-09  
**POC仓库:** [CVE-2018-11776-Python-PoC](https://github.com/hook-s3c/CVE-2018-11776-Python-PoC)  

---

### [CVE-2018-11776](CVE-2018-11776-bhdresh_CVE-2018-11776.md) 🔴 ✅

**名称:** CVE-2018-11776-Apache Struts远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，允许攻击者在服务器上执行任意命令。  
**投毒风险:** 5%  
**发现时间:** 2025-09-09  
**POC仓库:** [CVE-2018-11776](https://github.com/bhdresh/CVE-2018-11776)  

---

### [CVE-2018-11776](CVE-2018-11776-knqyf263_CVE-2018-11776.md) 🔴 ✅

**名称:** CVE-2018-11776-Apache Struts-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-09-09  
**POC仓库:** [CVE-2018-11776](https://github.com/knqyf263/CVE-2018-11776)  

---

### [CVE-2018-11776](CVE-2018-11776-mazen160_struts-pwn_CVE-2018-11776.md) 🔴 ✅

**名称:** CVE-2018-11776-Apache Struts2 远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-09-09  
**POC仓库:** [struts-pwn_CVE-2018-11776](https://github.com/mazen160/struts-pwn_CVE-2018-11776)  

---

### [CVE-2018-11776](CVE-2018-11776-brianwrf_S2-057-CVE-2018-11776.md) 🔴 ✅

**名称:** CVE-2018-11776 Apache Struts 远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 5%  
**发现时间:** 2025-09-09  
**POC仓库:** [S2-057-CVE-2018-11776](https://github.com/brianwrf/S2-057-CVE-2018-11776)  

---

### [CVE-2018-11776](CVE-2018-11776-tuxotron_cve-2018-11776-docker.md) 🔴 ✅

**名称:** CVE-2018-11776-Apache Struts2-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-09-09  
**POC仓库:** [cve-2018-11776-docker](https://github.com/tuxotron/cve-2018-11776-docker)  

---

### [CVE-2018-11776](CVE-2018-11776-649_Apache-Struts-Shodan-Exploit.md) 🔴 ✅

**名称:** CVE-2018-11776-Apache Struts 远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-09-09  
**POC仓库:** [Apache-Struts-Shodan-Exploit](https://github.com/649/Apache-Struts-Shodan-Exploit)  

---

### [CVE-2018-11776](CVE-2018-11776-Ekultek_Strutter.md) 🔴 ✅

**名称:** CVE-2018-11776-Apache Struts远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-09-09  
**POC仓库:** [Strutter](https://github.com/Ekultek/Strutter)  

---

### [CVE-2018-11776](CVE-2018-11776-cucadili_CVE-2018-11776.md) 🔴 ✅

**名称:** CVE-2018-11776 Apache Struts2 远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，允许未经身份验证的远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-09-09  
**POC仓库:** [CVE-2018-11776](https://github.com/cucadili/CVE-2018-11776)  

---

### [CVE-2018-11776](CVE-2018-11776-xfox64x_CVE-2018-11776.md) 🔴 ✅

**名称:** CVE-2018-11776 - Apache Struts Remote Code Execution  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 1%  
**发现时间:** 2025-09-09  
**POC仓库:** [CVE-2018-11776](https://github.com/xfox64x/CVE-2018-11776)  

---

### [CVE-2018-11776](CVE-2018-11776-freshdemo_ApacheStruts-CVE-2018-11776.md) 🔴 ✅

**名称:** CVE-2018-11776-Apache Struts2-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-09-09  
**POC仓库:** [ApacheStruts-CVE-2018-11776](https://github.com/freshdemo/ApacheStruts-CVE-2018-11776)  

---

### [CVE-2018-11776](CVE-2018-11776-arlyone_Apache-Struts-0Day-Exploit.md) 🔴 ✅

**名称:** CVE-2018-11776-Apache Struts-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 1%  
**发现时间:** 2025-09-09  
**POC仓库:** [Apache-Struts-0Day-Exploit](https://github.com/arlyone/Apache-Struts-0Day-Exploit)  

---

### [CVE-2018-11776](CVE-2018-11776-cved-sources_cve-2018-11776.md) 🔴 ✅

**名称:** CVE-2018-11776 Apache Struts 远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可导致服务器被完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-09-09  
**POC仓库:** [cve-2018-11776](https://github.com/cved-sources/cve-2018-11776)  

---

### [CVE-2018-11776](CVE-2018-11776-OzNetNerd_apche-struts-vuln-demo-cve-2018-11776.md) 🔴 ✅

**名称:** CVE-2018-11776-Apache Struts远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-09-09  
**POC仓库:** [apche-struts-vuln-demo-cve-2018-11776](https://github.com/OzNetNerd/apche-struts-vuln-demo-cve-2018-11776)  

---

### [CVE-2018-11776](CVE-2018-11776-sonpt-afk_CVE-2018-11776-FIS.md) 🔴 ✅

**名称:** CVE-2018-11776-Apache Struts 远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可导致远程代码执行，完全控制服务器  
**投毒风险:** 10%  
**发现时间:** 2025-09-09  
**POC仓库:** [CVE-2018-11776-FIS](https://github.com/sonpt-afk/CVE-2018-11776-FIS)  

---

### [CVE-2018-11776](CVE-2018-11776-jiguangsdf_CVE-2018-11776.md) 🔴 ✅

**名称:** CVE-2018-11776-Apache Struts 远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-09-09  
**POC仓库:** [CVE-2018-11776](https://github.com/jiguangsdf/CVE-2018-11776)  

---

### [CVE-2018-11776](CVE-2018-11776-m4sk0ff_CVE-2018-11776.md) 🔴 ✅

**名称:** CVE-2018-11776-Apache Struts 远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可以远程执行任意代码，完全控制服务器  
**投毒风险:** 0%  
**发现时间:** 2025-09-09  
**POC仓库:** [CVE-2018-11776](https://github.com/m4sk0ff/CVE-2018-11776)  

---

### [CVE-2019-9053](CVE-2019-9053-Slayerma_-CVE-2019-9053.md) 🔴 ✅

**名称:** CVE-2019-9053 - CMS Made Simple SQL注入  
**类型:** SQL注入 (Blind Time-Based)  
**风险:** 高危，可能导致数据泄露和权限提升  
**投毒风险:** 10%  
**发现时间:** 2025-09-09  
**POC仓库:** [-CVE-2019-9053](https://github.com/Slayerma/-CVE-2019-9053)  

---

### [CVE-2025-57833](CVE-2025-57833-loic-houchi_Django-faille-CVE-2025-57833_test.md) 🔴 ✅

**名称:** CVE-2025-57833 Django FilteredRelation SQL 注入  
**类型:** SQL 注入  
**风险:** 高危，可能导致数据泄露、数据篡改和远程代码执行  
**投毒风险:** 20%  
**发现时间:** 2025-09-09  
**POC仓库:** [Django-faille-CVE-2025-57833_test](https://github.com/loic-houchi/Django-faille-CVE-2025-57833_test)  

---

### [CVE-2024-28397](CVE-2024-28397-naclapor_CVE-2024-28397.md) 🔴 ✅

**名称:** CVE-2024-28397-js2py沙箱逃逸  
**类型:** 沙箱逃逸/远程代码执行  
**风险:** 高危，允许攻击者执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-09-09  
**POC仓库:** [CVE-2024-28397](https://github.com/naclapor/CVE-2024-28397)  

---

### [CVE-2025-58180](CVE-2025-58180-prabhatverma47_CVE-2025-58180-RCE-in-OctoPrint-via-Unsanitized-Filename.md) 🔴 ✅

**名称:** CVE-2025-58180 OctoPrint RCE via Unsanitized Filename  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-09-09  
**POC仓库:** [CVE-2025-58180-RCE-in-OctoPrint-via-Unsanitized-Filename](https://github.com/prabhatverma47/CVE-2025-58180-RCE-in-OctoPrint-via-Unsanitized-Filename)  

---

### [CVE-2018-16763](CVE-2018-16763-0xPwd_CVE-2018-16763_FuelCMS-1.4.1_RCE.md) 🔴 ✅

**名称:** CVE-2018-16763_FuelCMS-1.4.1_RCE  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-09-09  
**POC仓库:** [CVE-2018-16763_FuelCMS-1.4.1_RCE](https://github.com/0xPwd/CVE-2018-16763_FuelCMS-1.4.1_RCE)  

---

### [CVE-2025-48384](CVE-2025-48384-EdwardYeIntrix_CVE-2025-48384-Scanner.md) 🔴 ✅

**名称:** CVE-2025-48384-Git代码执行  
**类型:** 代码执行  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-09-09  
**POC仓库:** [CVE-2025-48384-Scanner](https://github.com/EdwardYeIntrix/CVE-2025-48384-Scanner)  

---

### [CVE-2025-24204](CVE-2025-24204-34306_decrypted.md) 🔴 ✅

**名称:** CVE-2025-24204-macOS-用户数据访问  
**类型:** 敏感信息泄露  
**风险:** 高危，可能导致敏感用户数据泄露  
**投毒风险:** 10%  
**发现时间:** 2025-09-09  
**POC仓库:** [decrypted](https://github.com/34306/decrypted)  

---

### [CVE-2025-24204](CVE-2025-24204-FFRI_CVE-2025-24204.md) 🔴 ✅

**名称:** CVE-2025-24204-macOS-用户数据访问  
**类型:** 用户数据访问  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-09-09  
**POC仓库:** [CVE-2025-24204](https://github.com/FFRI/CVE-2025-24204)  

---

### [CVE-2025-24204](CVE-2025-24204-bale170501_decrypted.md) 🔴 ✅

**名称:** CVE-2025-24204 - macOS User Data Access  
**类型:** 权限提升/信息泄露  
**风险:** 高危，可能导致敏感用户数据泄露  
**投毒风险:** 80%  
**发现时间:** 2025-09-09  
**POC仓库:** [decrypted](https://github.com/bale170501/decrypted)  

---

### [CVE-2024-6387](CVE-2024-6387-moften_regreSSHion-CVE-2024-6387.md) 🔴 ✅

**名称:** CVE-2024-6387-OpenSSH-竞争条件导致RCE/DoS  
**类型:** 竞争条件  
**风险:** 高危，可能导致远程代码执行和拒绝服务  
**投毒风险:** 1%  
**发现时间:** 2025-09-08  
**POC仓库:** [regreSSHion-CVE-2024-6387](https://github.com/moften/regreSSHion-CVE-2024-6387)  

---

### [CVE-2022-22077](CVE-2022-22077-grisuno_CVE-2022-22077.md) 🔴 

**名称:** CVE-2022-22077  
**类型:** Use-After-Free  
**风险:** 高危，可能导致内存破坏、代码执行、信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-09-08  
**POC仓库:** [CVE-2022-22077](https://github.com/grisuno/CVE-2022-22077)  

---

### [CVE-2025-30208](CVE-2025-30208-Dany60-98_CVE-2025-30208-EXP.md) 🟡 ✅

**名称:** CVE-2025-30208-Vite-任意文件读取  
**类型:** 任意文件读取  
**风险:** 中危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-09-08  
**POC仓库:** [CVE-2025-30208-EXP](https://github.com/Dany60-98/CVE-2025-30208-EXP)  

---

### [CVE-2025-42957](CVE-2025-42957-callinston_CVE-2025-42957.md) 🔴 ✅

**名称:** CVE-2025-42957 SAP S/4HANA ABAP 代码注入  
**类型:** ABAP 代码注入  
**风险:** 高危，可完全控制系统，导致数据泄露、篡改和拒绝服务  
**投毒风险:** 10%  
**发现时间:** 2025-09-08  
**POC仓库:** [CVE-2025-42957](https://github.com/callinston/CVE-2025-42957)  

---

### [CVE-2025-24813](CVE-2025-24813-Makavellik_POC-CVE-2025-24813-Apache-Tomcat-Remote-Code-Execution.md) 🔴 ✅

**名称:** CVE-2025-24813 - Apache Tomcat 远程代码执行  
**类型:** 远程代码执行 (RCE) / 信息泄露  
**风险:** 高危，可能导致远程代码执行，信息泄露或恶意内容注入  
**投毒风险:** 10%  
**发现时间:** 2025-09-08  
**POC仓库:** [POC-CVE-2025-24813-Apache-Tomcat-Remote-Code-Execution](https://github.com/Makavellik/POC-CVE-2025-24813-Apache-Tomcat-Remote-Code-Execution)  

---

### [CVE-2012-2982](CVE-2012-2982-boritopalito_CVE-2012-2982.md) 🔴 ✅

**名称:** CVE-2012-2982-Webmin-命令注入  
**类型:** 命令注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-09-08  
**POC仓库:** [CVE-2012-2982](https://github.com/boritopalito/CVE-2012-2982)  

---

### [CVE-2024-835](CVE-2024-835-melmathari_dockerCVE-2024-835.md) 🟡 ✅

**名称:** WordPress Docker Compose 环境配置  
**类型:** Docker Compose配置不当  
**风险:** 中危，可能导致未经授权的访问或数据泄露  
**投毒风险:** 10%  
**发现时间:** 2025-09-08  
**POC仓库:** [dockerCVE-2024-835](https://github.com/melmathari/dockerCVE-2024-835)  

---

### [CVE-2025-57055](CVE-2025-57055-thawphone_CVE-2025-57055.md) 🔴 ✅

**名称:** CVE-2025-57055: WonderCMS 3.5.0 Authenticated Remote Code Execution  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-09-08  
**POC仓库:** [CVE-2025-57055](https://github.com/thawphone/CVE-2025-57055)  

---

### [CVE-2025-24799](CVE-2025-24799-nak000_CVE-2025-24799-sqli.md) 🔴 ✅

**名称:** CVE-2025-24799 GLPI 未授权SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露  
**投毒风险:** 10%  
**发现时间:** 2025-09-08  
**POC仓库:** [CVE-2025-24799-sqli](https://github.com/nak000/CVE-2025-24799-sqli)  

---

### [CVE-2025-24799](CVE-2025-24799-Rosemary1337_CVE-2025-24799.md) 🔴 ✅

**名称:** CVE-2025-24799-GLPI-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露  
**投毒风险:** 80%  
**发现时间:** 2025-09-08  
**POC仓库:** [CVE-2025-24799](https://github.com/Rosemary1337/CVE-2025-24799)  

---

### [CVE-2025-6934](CVE-2025-6934-Rosemary1337_CVE-2025-6934.md)  ✅

**名称:** CVE-2025-6934 - Opal Estate Pro Unauthenticated Privilege Escalation  
**类型:** 权限提升  
**风险:** 严重，允许未经身份验证的攻击者创建管理员账户  
**投毒风险:** 20%  
**发现时间:** 2025-09-08  
**POC仓库:** [CVE-2025-6934](https://github.com/Rosemary1337/CVE-2025-6934)  

---

### [CVE-2025-57819](CVE-2025-57819-B1ack4sh_Blackash-CVE-2025-57819.md)  ✅

**名称:** CVE-2025-57819-FreePBX-身份验证绕过导致SQL注入和RCE  
**类型:** 身份验证绕过, SQL注入, 远程代码执行  
**风险:** 严重，可能导致完全控制FreePBX系统  
**投毒风险:** 10%  
**发现时间:** 2025-09-08  
**POC仓库:** [Blackash-CVE-2025-57819](https://github.com/B1ack4sh/Blackash-CVE-2025-57819)  

---

### [CVE-2025-21333](CVE-2025-21333-pradip022_CVE-2025-21333-POC.md) 🔴 ✅

**名称:** CVE-2025-21333 Windows Hyper-V NT Kernel Integration VSP Elevation of Privilege  
**类型:** 权限提升  
**风险:** 高危，可提升权限  
**投毒风险:** 30%  
**发现时间:** 2025-09-08  
**POC仓库:** [CVE-2025-21333-POC](https://github.com/pradip022/CVE-2025-21333-POC)  

---

### [CVE-2023-51770](CVE-2023-51770-shoucheng3_apache__dolphinscheduler_CVE-2023-51770_3_2_1_fixed.md) 🔴 ✅

**名称:** CVE-2023-51770-Apache DolphinScheduler-任意文件读取  
**类型:** 任意文件读取  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-09-08  
**POC仓库:** [apache__dolphinscheduler_CVE-2023-51770_3_2_1_fixed](https://github.com/shoucheng3/apache__dolphinscheduler_CVE-2023-51770_3_2_1_fixed)  

---

### [CVE-2024-10220](CVE-2024-10220-mrk336_CVE-2024-10220-Kubernetes-gitRepo-Volume-Vulnerability.md) 🔴 ✅

**名称:** CVE-2024-10220-Kubernetes-gitRepo-Volume-任意命令执行  
**类型:** 任意命令执行  
**风险:** 高危，允许低权限用户在主机节点上执行任意命令  
**投毒风险:** 0%  
**发现时间:** 2025-09-08  
**POC仓库:** [CVE-2024-10220-Kubernetes-gitRepo-Volume-Vulnerability](https://github.com/mrk336/CVE-2024-10220-Kubernetes-gitRepo-Volume-Vulnerability)  

---

### [CVE-2025-54914](CVE-2025-54914-mrk336_Azure-Networking-Privilege-Escalation-Exploit-CVE-2025-54914.md) 🔴 ✅

**名称:** CVE-2025-54914-Azure Networking Elevation of Privilege  
**类型:** 权限提升  
**风险:** 高危，可能导致未经授权的访问和控制Azure Networking资源  
**投毒风险:** 10%  
**发现时间:** 2025-09-08  
**POC仓库:** [Azure-Networking-Privilege-Escalation-Exploit-CVE-2025-54914](https://github.com/mrk336/Azure-Networking-Privilege-Escalation-Exploit-CVE-2025-54914)  

---

### [CVE-2025-52970](CVE-2025-52970-34zY_CVE-2025-52970.md) 🔴 ✅

**名称:** CVE-2025-52970-FortiWeb-身份验证绕过和远程代码执行  
**类型:** 身份验证绕过和远程代码执行  
**风险:** 高危，可导致完全控制受影响的 FortiWeb 设备  
**投毒风险:** 10%  
**发现时间:** 2025-09-07  
**POC仓库:** [CVE-2025-52970](https://github.com/34zY/CVE-2025-52970)  

---

### [CVE-2025-53772](CVE-2025-53772-fortihack_CVE-2025-53772.md) 🔴 

**名称:** CVE-2025-53772-Web Deploy远程代码执行  
**类型:** 反序列化漏洞  
**风险:** 高危，可远程代码执行  
**投毒风险:** 85%  
**发现时间:** 2025-09-07  
**POC仓库:** [CVE-2025-53772](https://github.com/fortihack/CVE-2025-53772)  

---

### [CVE-2025-32433](CVE-2025-32433-dollarboysushil_CVE-2025-32433-Erlang-OTP-SSH-Unauthenticated-RCE.md)  ✅

**名称:** CVE-2025-32433-Erlang/OTP SSH 远程代码执行  
**类型:** 远程代码执行  
**风险:** 严重，未经身份验证的远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-09-07  
**POC仓库:** [CVE-2025-32433-Erlang-OTP-SSH-Unauthenticated-RCE](https://github.com/dollarboysushil/CVE-2025-32433-Erlang-OTP-SSH-Unauthenticated-RCE)  

---

### [CVE-2019-9053](CVE-2019-9053-noob-hacker572_CMS-Made-Simple-2.2.9-CVE-2019-9053.md) 🔴 ✅

**名称:** CVE-2019-9053-CMS Made Simple-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露，权限提升  
**投毒风险:** 10%  
**发现时间:** 2025-09-07  
**POC仓库:** [CMS-Made-Simple-2.2.9-CVE-2019-9053](https://github.com/noob-hacker572/CMS-Made-Simple-2.2.9-CVE-2019-9053)  

---

### [CVE-2025-23266](CVE-2025-23266-mrk336_CVE-2025-23266.md) 🔴 ✅

**名称:** CVE-2025-23266-NVIDIA Container Toolkit-容器逃逸  
**类型:** 容器逃逸  
**风险:** 高危，可能导致权限提升、数据篡改、信息泄露和拒绝服务  
**投毒风险:** 10%  
**发现时间:** 2025-09-07  
**POC仓库:** [CVE-2025-23266](https://github.com/mrk336/CVE-2025-23266)  

---

### [CVE-2025-53690](CVE-2025-53690-m0d0ri205_CVE-2025-53690-Analysis.md) 🔴 ✅

**名称:** CVE-2025-53690-Sitecore ViewState Deserialization  
**类型:** 反序列化漏洞  
**风险:** 高危，远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-09-07  
**POC仓库:** [CVE-2025-53690-Analysis](https://github.com/m0d0ri205/CVE-2025-53690-Analysis)  

---

### [CVE-2025-0411](CVE-2025-0411-RustMacrosRecoil_7-Zip-CVE-2025-0411-POC.md) 🔴 

**名称:** CVE-2025-0411 7-Zip Mark-of-the-Web 绕过漏洞  
**类型:** Mark-of-the-Web (MotW) 绕过  
**风险:** 高危，可能导致任意代码执行  
**投毒风险:** 95%  
**发现时间:** 2025-09-07  
**POC仓库:** [7-Zip-CVE-2025-0411-POC](https://github.com/RustMacrosRecoil/7-Zip-CVE-2025-0411-POC)  

---

### [CVE-2025-10046](CVE-2025-10046-byteReaper77_CVE-2025-10046.md) 🟡 ✅

**名称:** CVE-2025-10046 - ELEX WooCommerce Google Shopping (Google Product Feed) SQL 注入  
**类型:** SQL 注入  
**风险:** 中危，可能导致敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-09-07  
**POC仓库:** [CVE-2025-10046](https://github.com/byteReaper77/CVE-2025-10046)  

---

### [CVE-2018-6574](CVE-2018-6574-AshrSec_pentesterlab-CVE-2018-6574.md) 🔴 ✅

**名称:** CVE-2018-6574-Go远程命令执行  
**类型:** 远程命令执行  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-09-06  
**POC仓库:** [pentesterlab-CVE-2018-6574](https://github.com/AshrSec/pentesterlab-CVE-2018-6574)  

---

### [CVE-2025-54309](CVE-2025-54309-whisperer1290_CVE-2025-54309__Enhanced_exploit.md) 🔴 ✅

**名称:** CVE-2025-54309 CrushFTP AS2验证绕过漏洞  
**类型:** 身份验证绕过  
**风险:** 高危，可获取管理员权限  
**投毒风险:** 10%  
**发现时间:** 2025-09-06  
**POC仓库:** [CVE-2025-54309__Enhanced_exploit](https://github.com/whisperer1290/CVE-2025-54309__Enhanced_exploit)  

---

### [CVE-2025-33073](CVE-2025-33073-cve-2025-33073_cve-2025-33073.md) 🔴 

**名称:** CVE-2025-33073 Windows SMB Client Elevation of Privilege  
**类型:** 权限提升  
**风险:** 高危，允许经过身份验证的攻击者在网络上提升权限  
**投毒风险:** 95%  
**发现时间:** 2025-09-06  
**POC仓库:** [cve-2025-33073](https://github.com/cve-2025-33073/cve-2025-33073)  

---

### [CVE-2025-52389](CVE-2025-52389-ktr4ck3r_CVE-2025-52389.md) 🔴 ✅

**名称:** CVE-2023-52389 - Envasadora H2O Eireli - Soda Cristal v40.20.4 IDOR  
**类型:** Insecure Direct Object Reference (IDOR)  
**风险:** 高危，可能导致敏感数据泄露  
**投毒风险:** 10%  
**发现时间:** 2025-09-06  
**POC仓库:** [CVE-2025-52389](https://github.com/ktr4ck3r/CVE-2025-52389)  

---

### [CVE-2025-8088](CVE-2025-8088-cozythrill_CVE-2025-8088.md) 🔴 ✅

**名称:** CVE-2025-8088 WinRAR 路径遍历漏洞  
**类型:** 路径遍历  
**风险:** 高危，可导致任意代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-09-06  
**POC仓库:** [CVE-2025-8088](https://github.com/cozythrill/CVE-2025-8088)  

---

### [CVE-2015-5736](CVE-2015-5736-avielzecharia_CVE-2015-5736.md) 🔴 ✅

**名称:** CVE-2015-5736 - Fortinet FortiClient 本地提权  
**类型:** 本地提权  
**风险:** 高危，允许本地用户以内核权限执行任意代码  
**投毒风险:** 5%  
**发现时间:** 2025-09-06  
**POC仓库:** [CVE-2015-5736](https://github.com/avielzecharia/CVE-2015-5736)  

---

### [CVE-2018-9159](CVE-2018-9159-shoucheng3_perwendel__spark_CVE-2018-9159_2_7_2_fixed.md) 🟡 ✅

**名称:** CVE-2018-9159-spark-core-文件读取  
**类型:** 文件读取  
**风险:** 中危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-09-06  
**POC仓库:** [perwendel__spark_CVE-2018-9159_2_7_2_fixed](https://github.com/shoucheng3/perwendel__spark_CVE-2018-9159_2_7_2_fixed)  

---

### [CVE-2019-10219](CVE-2019-10219-shoucheng3_hibernate__hibernate-validator_CVE-2019-10219_6_0_18_Final_fixed.md) 🟡 ✅

**名称:** CVE-2019-10219-Hibernate-Validator-XSS  
**类型:** XSS  
**风险:** 中危，可能导致用户信息泄露和恶意脚本执行  
**投毒风险:** 10%  
**发现时间:** 2025-09-06  
**POC仓库:** [hibernate__hibernate-validator_CVE-2019-10219_6_0_18_Final_fixed](https://github.com/shoucheng3/hibernate__hibernate-validator_CVE-2019-10219_6_0_18_Final_fixed)  

---

### [CVE-2019-10077](CVE-2019-10077-shoucheng3_apache__jspwiki_CVE-2019-10077_2_11_0_M4_fixed.md) 🟡 ✅

**名称:** CVE-2019-10077 - Apache JSPWiki InterWiki XSS  
**类型:** 跨站脚本 (XSS)  
**风险:** 中危，可能导致会话劫持  
**投毒风险:** 5%  
**发现时间:** 2025-09-06  
**POC仓库:** [apache__jspwiki_CVE-2019-10077_2_11_0_M4_fixed](https://github.com/shoucheng3/apache__jspwiki_CVE-2019-10077_2_11_0_M4_fixed)  

---

### [CVE-2024-28397](CVE-2024-28397-ExtremeUday_Remote-Code-Execution-CVE-2024-28397-pyload-ng-js2py-.md) 🔴 ✅

**名称:** CVE-2024-28397-js2py-Sandbox-Escape  
**类型:** 代码注入  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-09-06  
**POC仓库:** [Remote-Code-Execution-CVE-2024-28397-pyload-ng-js2py-](https://github.com/ExtremeUday/Remote-Code-Execution-CVE-2024-28397-pyload-ng-js2py-)  

---

### [CVE-2019-10078](CVE-2019-10078-shoucheng3_apache__jspwiki_CVE-2019-10078_2_11_0_M4_fixed.md) 🟡 ✅

**名称:** CVE-2019-10078-Apache JSPWiki-XSS  
**类型:** XSS  
**风险:** 中危，可能导致会话劫持  
**投毒风险:** 10%  
**发现时间:** 2025-09-06  
**POC仓库:** [apache__jspwiki_CVE-2019-10078_2_11_0_M4_fixed](https://github.com/shoucheng3/apache__jspwiki_CVE-2019-10078_2_11_0_M4_fixed)  

---

### [CVE-2020-8570](CVE-2020-8570-shoucheng3_kubernetes-client__java_CVE-2020-8570_client-java-parent-9_0_2_fixed.md) 🔴 ✅

**名称:** CVE-2020-8570 Kubernetes Java Client Path Traversal  
**类型:** 路径遍历  
**风险:** 高危，可能导致文件覆盖和系统妥协  
**投毒风险:** 1%  
**发现时间:** 2025-09-06  
**POC仓库:** [kubernetes-client__java_CVE-2020-8570_client-java-parent-9_0_2_fixed](https://github.com/shoucheng3/kubernetes-client__java_CVE-2020-8570_client-java-parent-9_0_2_fixed)  

---

### [CVE-2022-44262](CVE-2022-44262-shoucheng3_ff4j__ff4j_CVE-2022-44262_1_8_13_fixed.md)  

**名称:** CVE-2022-44262-ff4j-RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 严重，可能导致完全系统控制  
**投毒风险:** 0%  
**发现时间:** 2025-09-06  
**POC仓库:** [ff4j__ff4j_CVE-2022-44262_1_8_13_fixed](https://github.com/shoucheng3/ff4j__ff4j_CVE-2022-44262_1_8_13_fixed)  

---

### [CVE-2017-5638](CVE-2017-5638-MuhammadAbdullah192_CVE-2017-5638-Remote-Code-Execution-Apache-Struts2-EXPLOITATION.md) 🔴 ✅

**名称:** CVE-2017-5638-Apache Struts2 远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-09-06  
**POC仓库:** [CVE-2017-5638-Remote-Code-Execution-Apache-Struts2-EXPLOITATION](https://github.com/MuhammadAbdullah192/CVE-2017-5638-Remote-Code-Execution-Apache-Struts2-EXPLOITATION)  

---

### [CVE-2023-46818](CVE-2023-46818-zs1n_CVE-2023-46818.md) 🔴 ✅

**名称:** CVE-2023-46818-ISPConfig-PHP代码注入  
**类型:** PHP代码注入  
**风险:** 高危，可导致远程代码执行，完全控制服务器  
**投毒风险:** 5%  
**发现时间:** 2025-09-06  
**POC仓库:** [CVE-2023-46818](https://github.com/zs1n/CVE-2023-46818)  

---

### [CVE-2025-58443](CVE-2025-58443-casp3r0x0_CVE-2025-58443.md) 🔴 ✅

**名称:** CVE-2025-58443 - FOG Project Authentication Bypass  
**类型:** Authentication Bypass, SSRF, File Listing  
**风险:** 高危，可能导致数据库泄露、服务器端请求伪造和敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-09-06  
**POC仓库:** [CVE-2025-58443](https://github.com/casp3r0x0/CVE-2025-58443)  

---

### [CVE-2013-3900](CVE-2013-3900-oukridrig772_-WinVerifyTrust-Signature-Validation-CVE-2013-3900-Mitigation.md) 🔴 ✅

**名称:** CVE-2013-3900 WinVerifyTrust 签名验证漏洞  
**类型:** 签名验证绕过  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-09-06  
**POC仓库:** [-WinVerifyTrust-Signature-Validation-CVE-2013-3900-Mitigation](https://github.com/oukridrig772/-WinVerifyTrust-Signature-Validation-CVE-2013-3900-Mitigation)  

---

### [CVE-2021-42013](CVE-2021-42013-viliuspovilaika_cve-2021-42013.md) 🔴 ✅

**名称:** CVE-2021-42013 Apache HTTP Server Path Traversal and Remote Code Execution  
**类型:** Path Traversal and Remote Code Execution  
**风险:** 高危，允许攻击者读取任意文件和执行任意命令  
**投毒风险:** 5%  
**发现时间:** 2025-09-05  
**POC仓库:** [cve-2021-42013](https://github.com/viliuspovilaika/cve-2021-42013)  

---

### [CVE-2021-42013](CVE-2021-42013-jas9reet_CVE-2021-42013-LAB.md) 🔴 ✅

**名称:** CVE-2021-42013-Apache HTTP Server-路径遍历和远程代码执行  
**类型:** 路径遍历和远程代码执行  
**风险:** 高危，可能导致敏感信息泄露和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-09-05  
**POC仓库:** [CVE-2021-42013-LAB](https://github.com/jas9reet/CVE-2021-42013-LAB)  

---

### [CVE-2021-42013](CVE-2021-42013-Vulnmachines_cve-2021-42013.md) 🔴 ✅

**名称:** CVE-2021-42013-Apache HTTP Server-路径遍历与远程代码执行  
**类型:** 路径遍历与远程代码执行  
**风险:** 高危，可能导致敏感文件泄露和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-09-05  
**POC仓库:** [cve-2021-42013](https://github.com/Vulnmachines/cve-2021-42013)  

---

### [CVE-2021-42013](CVE-2021-42013-mightysai1997_cve-2021-42013.md) 🔴 ✅

**名称:** CVE-2021-42013 - Apache HTTP Server Path Traversal and Remote Code Execution  
**类型:** Path Traversal and Remote Code Execution  
**风险:** 高危，可能导致敏感信息泄露和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-09-05  
**POC仓库:** [cve-2021-42013](https://github.com/mightysai1997/cve-2021-42013)  

---

### [CVE-2021-42013](CVE-2021-42013-mightysai1997_cve-2021-42013L.md) 🔴 ✅

**名称:** CVE-2021-42013: Apache HTTP Server Path Traversal and Remote Code Execution  
**类型:** Path Traversal / Remote Code Execution  
**风险:** 高危，可能导致敏感信息泄露和远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-09-05  
**POC仓库:** [cve-2021-42013L](https://github.com/mightysai1997/cve-2021-42013L)  

---

### [CVE-2021-42013](CVE-2021-42013-mightysai1997_cve-2021-42013.get.md) 🔴 ✅

**名称:** CVE-2021-42013 - Apache HTTP Server Path Traversal 和远程代码执行  
**类型:** 路径遍历和远程代码执行  
**风险:** 高危，可能导致文件泄露和远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-09-05  
**POC仓库:** [cve-2021-42013.get](https://github.com/mightysai1997/cve-2021-42013.get)  

---

### [CVE-2021-42013](CVE-2021-42013-hadrian3689_apache_2.4.50.md) 🔴 ✅

**名称:** CVE-2021-42013 - Apache HTTP Server Path Traversal and Remote Code Execution  
**类型:** Path Traversal / Remote Code Execution  
**风险:** 高危，可能导致敏感信息泄露和服务器完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-09-05  
**POC仓库:** [apache_2.4.50](https://github.com/hadrian3689/apache_2.4.50)  

---

### [CVE-2021-42013](CVE-2021-42013-12345qwert123456_CVE-2021-42013.md) 🔴 ✅

**名称:** CVE-2021-42013 - Apache HTTP Server Path Traversal and Remote Code Execution  
**类型:** Path Traversal and Remote Code Execution  
**风险:** 高危，可能导致敏感文件泄露和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-09-05  
**POC仓库:** [CVE-2021-42013](https://github.com/12345qwert123456/CVE-2021-42013)  

---

### [CVE-2021-42013](CVE-2021-42013-walnutsecurity_cve-2021-42013.md) 🔴 ✅

**名称:** CVE-2021-42013 - Apache HTTP Server Path Traversal 和 Remote Code Execution  
**类型:** 路径遍历和远程代码执行  
**风险:** 高危，可能导致敏感文件泄露和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-09-05  
**POC仓库:** [cve-2021-42013](https://github.com/walnutsecurity/cve-2021-42013)  

---

### [CVE-2021-42013](CVE-2021-42013-cybfar_cve-2021-42013-httpd.md) 🔴 ✅

**名称:** CVE-2021-42013 - Apache HTTP Server Path Traversal and Remote Code Execution  
**类型:** 路径遍历和远程代码执行  
**风险:** 高危，可能导致敏感信息泄露和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-09-05  
**POC仓库:** [cve-2021-42013-httpd](https://github.com/cybfar/cve-2021-42013-httpd)  

---

### [CVE-2021-42013](CVE-2021-42013-vudala_CVE-2021-42013.md) 🔴 ✅

**名称:** CVE-2021-42013-Apache HTTP Server-路径遍历和远程代码执行  
**类型:** 路径遍历和远程代码执行  
**风险:** 高危，可能导致敏感信息泄露和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-09-05  
**POC仓库:** [CVE-2021-42013](https://github.com/vudala/CVE-2021-42013)  

---

### [CVE-2021-42013](CVE-2021-42013-Hamesawian_CVE-2021-42013.md) 🔴 ✅

**名称:** CVE-2021-42013-Apache HTTP Server-路径遍历和远程代码执行  
**类型:** 路径遍历和远程代码执行  
**风险:** 高危，可能导致敏感信息泄露和远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-09-05  
**POC仓库:** [CVE-2021-42013](https://github.com/Hamesawian/CVE-2021-42013)  

---

### [CVE-2021-42013](CVE-2021-42013-K3ysTr0K3R_CVE-2021-42013-EXPLOIT.md) 🔴 ✅

**名称:** CVE-2021-42013 - Apache HTTP Server Path Traversal and Remote Code Execution  
**类型:** 路径遍历和远程代码执行  
**风险:** 高危，可能导致敏感信息泄露和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-09-05  
**POC仓库:** [CVE-2021-42013-EXPLOIT](https://github.com/K3ysTr0K3R/CVE-2021-42013-EXPLOIT)  

---

### [CVE-2021-42013](CVE-2021-42013-BassoNicolas_CVE-2021-42013.md) 🔴 ✅

**名称:** CVE-2021-42013 - Apache HTTP Server Path Traversal 和 RCE  
**类型:** 路径遍历和远程代码执行  
**风险:** 高危，允许未经身份验证的远程攻击者读取任意文件和执行任意代码  
**投毒风险:** 0%  
**发现时间:** 2025-09-05  
**POC仓库:** [CVE-2021-42013](https://github.com/BassoNicolas/CVE-2021-42013)  

---

### [CVE-2021-42013](CVE-2021-42013-bananoname_cve-2021-42013.md) 🔴 ✅

**名称:** CVE-2021-42013-Apache HTTP Server-Path Traversal 和 Remote Code Execution  
**类型:** Path Traversal 和 Remote Code Execution  
**风险:** 高危，可能导致敏感信息泄露和服务器被完全控制  
**投毒风险:** 5%  
**发现时间:** 2025-09-05  
**POC仓库:** [cve-2021-42013](https://github.com/bananoname/cve-2021-42013)  

---

### [CVE-2021-42013](CVE-2021-42013-asepsaepdin_CVE-2021-42013.md) 🔴 ✅

**名称:** CVE-2021-42013 - Apache HTTP Server Path Traversal & Remote Code Execution  
**类型:** 路径遍历和远程代码执行  
**风险:** 高危，可能导致敏感信息泄露和远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-09-05  
**POC仓库:** [CVE-2021-42013](https://github.com/asepsaepdin/CVE-2021-42013)  

---

### [CVE-2021-42013](CVE-2021-42013-dream434_cve-2021-42013-apache.md) 🔴 ✅

**名称:** CVE-2021-42013 - Apache HTTP Server Path Traversal 和 RCE  
**类型:** 路径遍历和远程代码执行  
**风险:** 高危，可能导致信息泄露和远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-09-05  
**POC仓库:** [cve-2021-42013-apache](https://github.com/dream434/cve-2021-42013-apache)  

---

### [CVE-2021-42013](CVE-2021-42013-Makavellik_POC-CVE-2021-42013-EXPLOIT.md) 🔴 ✅

**名称:** CVE-2021-42013 - Apache HTTP Server Path Traversal 和远程代码执行  
**类型:** Path Traversal/远程代码执行  
**风险:** 高危，可能导致敏感信息泄露和服务器控制  
**投毒风险:** 10%  
**发现时间:** 2025-09-05  
**POC仓库:** [POC-CVE-2021-42013-EXPLOIT](https://github.com/Makavellik/POC-CVE-2021-42013-EXPLOIT)  

---

### [CVE-2025-24893](CVE-2025-24893-andwati_CVE-2025-24893.md) 🔴 ✅

**名称:** CVE-2025-24893-XWiki-RCE  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-09-05  
**POC仓库:** [CVE-2025-24893](https://github.com/andwati/CVE-2025-24893)  

---

### [CVE-2022-3141](CVE-2022-3141-Tomoe-12_CVE_2022_3141.md) 🔴 ✅

**名称:** CVE-2022-3141 - WordPress TranslatePress插件SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露和权限提升  
**投毒风险:** 95%  
**发现时间:** 2025-09-05  
**POC仓库:** [CVE_2022_3141](https://github.com/Tomoe-12/CVE_2022_3141)  

---

### [CVE-2025-53690](CVE-2025-53690-B1ack4sh_Blackash-CVE-2025-53690.md) 🔴 ✅

**名称:** CVE-2025-53690-Sitecore XM/XP-反序列化漏洞  
**类型:** 反序列化漏洞  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-09-05  
**POC仓库:** [Blackash-CVE-2025-53690](https://github.com/B1ack4sh/Blackash-CVE-2025-53690)  

---

### [CVE-2025-58780](CVE-2025-58780-SexyShoelessGodofWar_CVE-2025-58780.md) 🔴 ✅

**名称:** CVE-2025-58780 - ScienceLogic SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致未授权访问敏感数据或控制数据库  
**投毒风险:** 10%  
**发现时间:** 2025-09-05  
**POC仓库:** [CVE-2025-58780](https://github.com/SexyShoelessGodofWar/CVE-2025-58780)  

---

### [CVE-2025-49388](CVE-2025-49388-Nxploited_CVE-2025-49388.md) 🔴 ✅

**名称:** CVE-2025-49388-MiraculousCore-PrivilegeEscalation  
**类型:** 权限提升  
**风险:** 高危，允许未经授权的用户获得管理员权限  
**投毒风险:** 1%  
**发现时间:** 2025-09-05  
**POC仓库:** [CVE-2025-49388](https://github.com/Nxploited/CVE-2025-49388)  

---

### [CVE-2025-32463](CVE-2025-32463-blackcat4347_CVE-2025-32463_PoC.md) 🔴 ✅

**名称:** CVE-2025-32463-Sudo-本地权限提升  
**类型:** 本地权限提升  
**风险:** 高危，允许本地用户获取root权限  
**投毒风险:** 0%  
**发现时间:** 2025-09-05  
**POC仓库:** [CVE-2025-32463_PoC](https://github.com/blackcat4347/CVE-2025-32463_PoC)  

---

### [CVE-2025-2502](CVE-2025-2502-IHK-ONE_CVE-2025-2502.md) 🔴 ✅

**名称:** CVE-2025-2502-Lenovo PC Manager权限提升  
**类型:** 权限提升  
**风险:** 高危，本地权限提升至SYSTEM  
**投毒风险:** 10%  
**发现时间:** 2025-09-05  
**POC仓库:** [CVE-2025-2502](https://github.com/IHK-ONE/CVE-2025-2502)  

---

### [CVE-2025-9074](CVE-2025-9074-ThemeHackers_CVE-2025-9074.md) 🔴 ✅

**名称:** CVE-2025-9074-Docker Desktop-API未授权访问  
**类型:** API未授权访问  
**风险:** 高危，可能导致容器逃逸和宿主机控制  
**投毒风险:** 10%  
**发现时间:** 2025-09-05  
**POC仓库:** [CVE-2025-9074](https://github.com/ThemeHackers/CVE-2025-9074)  

---

### [CVE-2025-57833](CVE-2025-57833-Mkway_CVE-2025-57833.md) 🔴 ✅

**名称:** CVE-2025-57833-Django-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致信息泄露和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-09-05  
**POC仓库:** [CVE-2025-57833](https://github.com/Mkway/CVE-2025-57833)  

---

### [CVE-2025-22131](CVE-2025-22131-s0ck37_CVE-2025-22131-POC.md) 🟡 ✅

**名称:** CVE-2025-22131-PhpSpreadsheet-XSS  
**类型:** 跨站脚本 (XSS)  
**风险:** 中危，可能导致用户信息泄露和恶意脚本执行  
**投毒风险:** 0%  
**发现时间:** 2025-09-05  
**POC仓库:** [CVE-2025-22131-POC](https://github.com/s0ck37/CVE-2025-22131-POC)  

---

### [CVE-2025-24071](CVE-2025-24071-AC8999_CVE-2025-24071.md) 🟡 ✅

**名称:** CVE-2025-24071-Windows文件资源管理器欺骗漏洞  
**类型:** 信息泄露/NTLM哈希窃取  
**风险:** 中危，可能导致凭据泄露  
**投毒风险:** 5%  
**发现时间:** 2025-09-05  
**POC仓库:** [CVE-2025-24071](https://github.com/AC8999/CVE-2025-24071)  

---

### [CVE-2025-58440](CVE-2025-58440-ph-hitachi_CVE-2025-58440.md) 🔴 ✅

**名称:** CVE-2025-58440 - Laravel File Manager Remote Code Execution  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-09-05  
**POC仓库:** [CVE-2025-58440](https://github.com/ph-hitachi/CVE-2025-58440)  

---

### [CVE-2024-1086](CVE-2024-1086-Notselwyn_CVE-2024-1086.md) 🔴 ✅

**名称:** CVE-2024-1086-Linux Kernel nf_tables Use-After-Free  
**类型:** Use-After-Free  
**风险:** 高危，本地权限提升  
**投毒风险:** 5%  
**发现时间:** 2025-09-04  
**POC仓库:** [CVE-2024-1086](https://github.com/Notselwyn/CVE-2024-1086)  

---

### [CVE-2024-1086](CVE-2024-1086-CCIEVoice2009_CVE-2024-1086.md) 🔴 ✅

**名称:** CVE-2024-1086  
**类型:** Use-After-Free  
**风险:** 高危，本地权限提升  
**投毒风险:** 10%  
**发现时间:** 2025-09-04  
**POC仓库:** [CVE-2024-1086](https://github.com/CCIEVoice2009/CVE-2024-1086)  

---

### [CVE-2024-1086](CVE-2024-1086-Alicey0719_docker-POC_CVE-2024-1086.md) 🔴 ✅

**名称:** CVE-2024-1086 - Linux Kernel Use-After-Free in nf_tables  
**类型:** Use-After-Free  
**风险:** 高危，本地权限提升至 root  
**投毒风险:** 10%  
**发现时间:** 2025-09-04  
**POC仓库:** [docker-POC_CVE-2024-1086](https://github.com/Alicey0719/docker-POC_CVE-2024-1086)  

---

### [CVE-2024-1086](CVE-2024-1086-feely666_CVE-2024-1086.md) 🔴 ✅

**名称:** CVE-2024-1086  
**类型:** Use-After-Free  
**风险:** 高危，本地权限提升  
**投毒风险:** 0%  
**发现时间:** 2025-09-04  
**POC仓库:** [CVE-2024-1086](https://github.com/feely666/CVE-2024-1086)  

---

### [CVE-2024-1086](CVE-2024-1086-kevcooper_CVE-2024-1086-checker.md) 🔴 ✅

**名称:** CVE-2024-1086 Linux Kernel Use-After-Free 特权提升  
**类型:** Use-After-Free  
**风险:** 高危，可能导致本地权限提升  
**投毒风险:** 5%  
**发现时间:** 2025-09-04  
**POC仓库:** [CVE-2024-1086-checker](https://github.com/kevcooper/CVE-2024-1086-checker)  

---

### [CVE-2024-1086](CVE-2024-1086-xzx482_CVE-2024-1086.md) 🔴 ✅

**名称:** CVE-2024-1086 - Linux Kernel Use-After-Free  
**类型:** Use-After-Free  
**风险:** 高危，本地权限提升  
**投毒风险:** 10%  
**发现时间:** 2025-09-04  
**POC仓库:** [CVE-2024-1086](https://github.com/xzx482/CVE-2024-1086)  

---

### [CVE-2024-1086](CVE-2024-1086-LLfam_CVE-2024-1086.md) 🔴 ✅

**名称:** CVE-2024-1086-Linux Kernel-Use-After-Free  
**类型:** Use-After-Free  
**风险:** 高危，可导致本地权限提升  
**投毒风险:** 10%  
**发现时间:** 2025-09-04  
**POC仓库:** [CVE-2024-1086](https://github.com/LLfam/CVE-2024-1086)  

---

### [CVE-2024-1086](CVE-2024-1086-karim4353_CVE-2024-1086-Exploit.md) 🔴 ✅

**名称:** CVE-2024-1086 Linux Kernel nf_tables Use-After-Free 本地提权漏洞  
**类型:** Use-After-Free  
**风险:** 高危，本地权限提升至root  
**投毒风险:** 10%  
**发现时间:** 2025-09-04  
**POC仓库:** [CVE-2024-1086-Exploit](https://github.com/karim4353/CVE-2024-1086-Exploit)  

---

### [CVE-2025-3515](CVE-2025-3515-MrSoules_lab-cve-2025-3515.md) 🔴 ✅

**名称:** CVE-2025-3515-Drag and Drop Multiple File Upload for Contact Form 7-任意文件上传  
**类型:** 任意文件上传  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-09-04  
**POC仓库:** [lab-cve-2025-3515](https://github.com/MrSoules/lab-cve-2025-3515)  

---

### [CVE-2025-24813](CVE-2025-24813-CEAlbez_CVE-2025-24813-PoC.md) 🔴 ✅

**名称:** CVE-2025-24813 - Apache Tomcat Path Equivalence/Partial PUT RCE/信息泄露  
**类型:** 路径等价/Partial PUT远程代码执行/信息泄露  
**风险:** 高危，可能导致远程代码执行和敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-09-04  
**POC仓库:** [CVE-2025-24813-PoC](https://github.com/CEAlbez/CVE-2025-24813-PoC)  

---

### [CVE-2016-15042](CVE-2016-15042-Aditya43621_lab-cve-2016-15042.md) 🔴 ✅

**名称:** CVE-2016-15042 - WordPress Plugin Arbitrary File Upload  
**类型:** 任意文件上传  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-09-04  
**POC仓库:** [lab-cve-2016-15042](https://github.com/Aditya43621/lab-cve-2016-15042)  

---

### [CVE-2025-53770](CVE-2025-53770-saladin0x1_CVE-2025-53770.md)  ✅

**名称:** CVE-2025-53770 - Microsoft SharePoint Server 远程代码执行漏洞  
**类型:** 远程代码执行 (RCE)  
**风险:** 严重，未经身份验证的攻击者可以通过网络执行任意代码。  
**投毒风险:** 10%  
**发现时间:** 2025-09-04  
**POC仓库:** [CVE-2025-53770](https://github.com/saladin0x1/CVE-2025-53770)  

---

### [CVE-2025-53690](CVE-2025-53690-rxerium_CVE-2025-53690.md) 🔴 ✅

**名称:** CVE-2025-53690-Sitecore-反序列化漏洞  
**类型:** 反序列化漏洞  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-09-04  
**POC仓库:** [CVE-2025-53690](https://github.com/rxerium/CVE-2025-53690)  

---

### [CVE-2023-50164](CVE-2023-50164-bcdannyboy_CVE-2023-50164.md) 🔴 ✅

**名称:** CVE-2023-50164 - Apache Struts 文件上传路径遍历导致远程代码执行  
**类型:** 路径遍历/远程代码执行  
**风险:** 高危，可能导致任意文件上传和远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-09-04  
**POC仓库:** [CVE-2023-50164](https://github.com/bcdannyboy/CVE-2023-50164)  

---

### [CVE-2023-50164](CVE-2023-50164-dwisiswant0_cve-2023-50164-poc.md) 🔴 ✅

**名称:** CVE-2023-50164-Apache Struts-路径遍历与远程代码执行  
**类型:** 路径遍历与远程代码执行  
**风险:** 高危，可能导致任意文件上传和远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-09-04  
**POC仓库:** [cve-2023-50164-poc](https://github.com/dwisiswant0/cve-2023-50164-poc)  

---

### [CVE-2023-50164](CVE-2023-50164-helsecert_cve-2023-50164.md) 🔴 ✅

**名称:** CVE-2023-50164 - Apache Struts 文件上传目录遍历导致远程代码执行  
**类型:** 目录遍历/远程代码执行  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-09-04  
**POC仓库:** [cve-2023-50164](https://github.com/helsecert/cve-2023-50164)  

---

### [CVE-2023-50164](CVE-2023-50164-Thirukrishnan_CVE-2023-50164-Apache-Struts-RCE.md) 🔴 ✅

**名称:** CVE-2023-50164-Apache Struts-RCE  
**类型:** 远程代码执行  
**风险:** 高危，可导致服务器被完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-09-04  
**POC仓库:** [CVE-2023-50164-Apache-Struts-RCE](https://github.com/Thirukrishnan/CVE-2023-50164-Apache-Struts-RCE)  

---

### [CVE-2023-50164](CVE-2023-50164-Trackflaw_CVE-2023-50164-ApacheStruts2-Docker.md) 🔴 ✅

**名称:** CVE-2023-50164-Apache Struts-文件上传路径穿越导致RCE  
**类型:** 文件上传路径穿越  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-09-04  
**POC仓库:** [CVE-2023-50164-ApacheStruts2-Docker](https://github.com/Trackflaw/CVE-2023-50164-ApacheStruts2-Docker)  

---

### [CVE-2023-50164](CVE-2023-50164-aaronm-sysdig_cve-2023-50164.md) 🔴 ✅

**名称:** CVE-2023-50164 - Apache Struts 文件上传路径遍历导致远程代码执行  
**类型:** 路径遍历/远程代码执行  
**风险:** 高危，可能导致远程代码执行和服务器控制  
**投毒风险:** 10%  
**发现时间:** 2025-09-04  
**POC仓库:** [cve-2023-50164](https://github.com/aaronm-sysdig/cve-2023-50164)  

---

### [CVE-2023-50164](CVE-2023-50164-sunnyvale-it_CVE-2023-50164-PoC.md) 🔴 ✅

**名称:** CVE-2023-50164-Apache Struts文件上传路径遍历导致RCE  
**类型:** 文件上传路径遍历导致RCE  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-09-04  
**POC仓库:** [CVE-2023-50164-PoC](https://github.com/sunnyvale-it/CVE-2023-50164-PoC)  

---

### [CVE-2023-50164](CVE-2023-50164-AsfandAliMemon25_CVE-2023-50164Analysis-.md) 🔴 ✅

**名称:** CVE-2023-50164-Apache Struts 文件上传路径遍历与RCE  
**类型:** 文件上传路径遍历/远程代码执行  
**风险:** 高危，可能导致远程代码执行和服务器控制  
**投毒风险:** 10%  
**发现时间:** 2025-09-04  
**POC仓库:** [CVE-2023-50164Analysis-](https://github.com/AsfandAliMemon25/CVE-2023-50164Analysis-)  

---

### [CVE-2023-50164](CVE-2023-50164-minhbao15677_CVE-2023-50164.md) 🔴 ✅

**名称:** CVE-2023-50164: Apache Struts 文件上传路径遍历导致RCE漏洞  
**类型:** 文件上传路径遍历导致远程代码执行  
**风险:** 高危，可导致任意文件上传和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-09-04  
**POC仓库:** [CVE-2023-50164](https://github.com/minhbao15677/CVE-2023-50164)  

---

### [CVE-2023-50164](CVE-2023-50164-jakabakos_CVE-2023-50164-Apache-Struts-RCE.md) 🔴 ✅

**名称:** CVE-2023-50164-Apache Struts文件上传路径遍历导致RCE  
**类型:** 路径遍历/远程代码执行  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-09-04  
**POC仓库:** [CVE-2023-50164-Apache-Struts-RCE](https://github.com/jakabakos/CVE-2023-50164-Apache-Struts-RCE)  

---

### [CVE-2023-50164](CVE-2023-50164-NikitaPark_CVE-2023-50164-PoC.md) 🔴 ✅

**名称:** CVE-2023-50164-Apache Struts-文件上传路径遍历RCE  
**类型:** 文件上传路径遍历RCE  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-09-04  
**POC仓库:** [CVE-2023-50164-PoC](https://github.com/NikitaPark/CVE-2023-50164-PoC)  

---

### [CVE-2023-50164](CVE-2023-50164-Pixel-DefaultBR_CVE-2023-50164.md) 🔴 ✅

**名称:** CVE-2023-50164 - Apache Struts 文件上传路径遍历与远程代码执行  
**类型:** 文件上传路径遍历与远程代码执行  
**风险:** 高危，可能导致服务器文件泄露，任意文件上传与远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-09-04  
**POC仓库:** [CVE-2023-50164](https://github.com/Pixel-DefaultBR/CVE-2023-50164)  

---

### [CVE-2023-50164](CVE-2023-50164-snyk-labs_CVE-2023-50164-POC.md) 🔴 ✅

**名称:** CVE-2023-50164-Apache Struts-路径遍历/远程代码执行  
**类型:** 路径遍历/远程代码执行  
**风险:** 高危，可能导致任意文件上传和远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-09-04  
**POC仓库:** [CVE-2023-50164-POC](https://github.com/snyk-labs/CVE-2023-50164-POC)  

---

### [CVE-2023-50164](CVE-2023-50164-MKIRAHMET_CVE-2023-50164-HTB-strutted.md) 🔴 ✅

**名称:** CVE-2023-50164: Apache Struts 文件上传路径遍历导致远程代码执行  
**类型:** 文件上传路径遍历导致远程代码执行  
**风险:** 高危，允许攻击者上传恶意文件并执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-09-04  
**POC仓库:** [CVE-2023-50164-HTB-strutted](https://github.com/MKIRAHMET/CVE-2023-50164-HTB-strutted)  

---

### [CVE-2021-21974](CVE-2021-21974-Shadow0ps_CVE-2021-21974.md) 🔴 ✅

**名称:** CVE-2021-21974 VMware ESXi OpenSLP 堆溢出漏洞  
**类型:** 堆溢出  
**风险:** 高危，远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-09-04  
**POC仓库:** [CVE-2021-21974](https://github.com/Shadow0ps/CVE-2021-21974)  

---

### [CVE-2021-21974](CVE-2021-21974-n2x4_Feb2023-CVE-2021-21974-OSINT.md) 🔴 ✅

**名称:** CVE-2021-21974 - VMware ESXi OpenSLP 堆溢出  
**类型:** 堆溢出  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 95%  
**发现时间:** 2025-09-04  
**POC仓库:** [Feb2023-CVE-2021-21974-OSINT](https://github.com/n2x4/Feb2023-CVE-2021-21974-OSINT)  

---

### [CVE-2021-21974](CVE-2021-21974-CYBERTHREATANALYSIS_ESXi-Ransomware-Scanner-mi.md) 🔴 ✅

**名称:** CVE-2021-21974 VMware ESXi OpenSLP 堆溢出  
**类型:** 堆溢出  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-09-04  
**POC仓库:** [ESXi-Ransomware-Scanner-mi](https://github.com/CYBERTHREATANALYSIS/ESXi-Ransomware-Scanner-mi)  

---

### [CVE-2021-21974](CVE-2021-21974-hateme021202_cve-2021-21974.md) 🔴 ✅

**名称:** CVE-2021-21974 - VMware ESXi OpenSLP 堆溢出  
**类型:** 堆溢出  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-09-04  
**POC仓库:** [cve-2021-21974](https://github.com/hateme021202/cve-2021-21974)  

---

### [CVE-2021-21974](CVE-2021-21974-mercylessghost_CVE-2021-21974.md) 🔴 ✅

**名称:** CVE-2021-21974-VMware ESXi-OpenSLP堆溢出  
**类型:** 堆溢出  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-09-04  
**POC仓库:** [CVE-2021-21974](https://github.com/mercylessghost/CVE-2021-21974)  

---

### [CVE-2021-21974](CVE-2021-21974-abirasecurity_CVE-2021-21974_vuln_dectection.md) 🔴 ✅

**名称:** CVE-2021-21974-VMware ESXi OpenSLP 堆溢出  
**类型:** 堆溢出  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-09-04  
**POC仓库:** [CVE-2021-21974_vuln_dectection](https://github.com/abirasecurity/CVE-2021-21974_vuln_dectection)  

---

### [CVE-2020-7961](CVE-2020-7961-thelostworldFree_CVE-2020-7961-payloads.md) 🔴 ✅

**名称:** CVE-2020-7961-Liferay Portal 反序列化RCE  
**类型:** 反序列化远程代码执行  
**风险:** 高危，可能导致远程代码执行，服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-09-04  
**POC仓库:** [CVE-2020-7961-payloads](https://github.com/thelostworldFree/CVE-2020-7961-payloads)  

---

### [CVE-2020-7961](CVE-2020-7961-mzer0one_CVE-2020-7961-POC.md) 🔴 ✅

**名称:** CVE-2020-7961-Liferay Portal-反序列化RCE  
**类型:** 反序列化远程代码执行  
**风险:** 高危，可能导致远程代码执行和系统完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-09-04  
**POC仓库:** [CVE-2020-7961-POC](https://github.com/mzer0one/CVE-2020-7961-POC)  

---

### [CVE-2020-7961](CVE-2020-7961-shacojx_LifeRCEJsonWSTool-POC-CVE-2020-7961-Gui.md) 🔴 ✅

**名称:** CVE-2020-7961 Liferay Portal JSONWS反序列化RCE  
**类型:** 反序列化漏洞  
**风险:** 高危，远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-09-04  
**POC仓库:** [LifeRCEJsonWSTool-POC-CVE-2020-7961-Gui](https://github.com/shacojx/LifeRCEJsonWSTool-POC-CVE-2020-7961-Gui)  

---

### [CVE-2020-7961](CVE-2020-7961-shacojx_GLiferay-CVE-2020-7961-golang.md) 🔴 ✅

**名称:** CVE-2020-7961-Liferay-Deserialization  
**类型:** 反序列化漏洞  
**风险:** 高危，允许远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-09-04  
**POC仓库:** [GLiferay-CVE-2020-7961-golang](https://github.com/shacojx/GLiferay-CVE-2020-7961-golang)  

---

### [CVE-2020-7961](CVE-2020-7961-shacojx_POC-CVE-2020-7961-Token-iterate.md) 🔴 ✅

**名称:** CVE-2020-7961 Liferay Portal 反序列化RCE  
**类型:** 反序列化RCE  
**风险:** 高危，允许远程攻击者执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-09-04  
**POC仓库:** [POC-CVE-2020-7961-Token-iterate](https://github.com/shacojx/POC-CVE-2020-7961-Token-iterate)  

---

### [CVE-2020-7961](CVE-2020-7961-CrackerCat_CVE-2020-7961-Mass.md) 🔴 ✅

**名称:** CVE-2020-7961-Liferay Portal反序列化RCE  
**类型:** 反序列化漏洞  
**风险:** 高危，远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-09-04  
**POC仓库:** [CVE-2020-7961-Mass](https://github.com/CrackerCat/CVE-2020-7961-Mass)  

---

### [CVE-2020-7961](CVE-2020-7961-ShutdownRepo_CVE-2020-7961.md) 🔴 ✅

**名称:** CVE-2020-7961 - Liferay Portal 反序列化远程代码执行  
**类型:** 反序列化漏洞  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-09-04  
**POC仓库:** [CVE-2020-7961](https://github.com/ShutdownRepo/CVE-2020-7961)  

---

### [CVE-2020-7961](CVE-2020-7961-pashayogi_CVE-2020-7961-Mass.md) 🔴 ✅

**名称:** CVE-2020-7961-Liferay Portal 反序列化RCE  
**类型:** 反序列化RCE  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 99%  
**发现时间:** 2025-09-04  
**POC仓库:** [CVE-2020-7961-Mass](https://github.com/pashayogi/CVE-2020-7961-Mass)  

---

### [CVE-2020-7961](CVE-2020-7961-neverhavenamee_CVE-2020-7961.md) 🔴 ✅

**名称:** CVE-2020-7961: Liferay Portal 反序列化导致远程代码执行  
**类型:** 反序列化漏洞  
**风险:** 高危，远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-09-04  
**POC仓库:** [CVE-2020-7961](https://github.com/neverhavenamee/CVE-2020-7961)  

---

### [CVE-2020-0610](CVE-2020-0610-Riocipta75_lab-cve-2020-0610.md) 🔴 ✅

**名称:** CVE-2020-0610 Windows Remote Desktop Gateway (RD Gateway) 远程代码执行漏洞  
**类型:** 远程代码执行  
**风险:** 高危，未经身份验证的攻击者可远程执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-09-04  
**POC仓库:** [lab-cve-2020-0610](https://github.com/Riocipta75/lab-cve-2020-0610)  

---

### [CVE-2025-8088](CVE-2025-8088-hexsecteam_CVE-2025-8088-Winrar-Tool.md) 🔴 ✅

**名称:** CVE-2025-8088 WinRAR Path Traversal  
**类型:** 路径遍历  
**风险:** 高危，可能导致任意代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-09-04  
**POC仓库:** [CVE-2025-8088-Winrar-Tool](https://github.com/hexsecteam/CVE-2025-8088-Winrar-Tool)  

---

### [CVE-2025-23266](CVE-2025-23266-Mindasy_cve-2025-23266-migration-bypass.md) 🔴 ✅

**名称:** CVE-2025-23266-NVIDIA Container Toolkit-权限提升/容器逃逸  
**类型:** 权限提升/容器逃逸  
**风险:** 高危，可能导致权限提升、数据篡改、信息泄露和拒绝服务  
**投毒风险:** 0%  
**发现时间:** 2025-09-04  
**POC仓库:** [cve-2025-23266-migration-bypass](https://github.com/Mindasy/cve-2025-23266-migration-bypass)  

---

### [CVE-2025-1055](CVE-2025-1055-diego-tella_CVE-2025-1055-poc.md) 🟡 ✅

**名称:** CVE-2025-1055 - K7RKScan.sys 任意进程终止  
**类型:** 权限提升/拒绝服务  
**风险:** 中危，可能导致系统服务中断  
**投毒风险:** 5%  
**发现时间:** 2025-09-04  
**POC仓库:** [CVE-2025-1055-poc](https://github.com/diego-tella/CVE-2025-1055-poc)  

---

### [CVE-2025-53772](CVE-2025-53772-Momollax_CVE-2025-53772-IIS-WebDeploy-RCE.md) 🔴 ✅

**名称:** CVE-2025-53772-Web Deploy Remote Code Execution  
**类型:** 反序列化漏洞导致的远程代码执行  
**风险:** 高危，允许未经授权的攻击者通过网络执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-09-04  
**POC仓库:** [CVE-2025-53772-IIS-WebDeploy-RCE](https://github.com/Momollax/CVE-2025-53772-IIS-WebDeploy-RCE)  

---

### [CVE-2025-8067](CVE-2025-8067-born0monday_CVE-2025-8067.md) 🔴 ✅

**名称:** CVE-2025-8067-Udisks-OOB Read  
**类型:** 越界读取 (Out-of-bounds Read)  
**风险:** 高危，可能导致信息泄露、权限提升和拒绝服务  
**投毒风险:** 0%  
**发现时间:** 2025-09-04  
**POC仓库:** [CVE-2025-8067](https://github.com/born0monday/CVE-2025-8067)  

---

### [CVE-2023-30990](CVE-2023-30990-silentsignal_CVE-2023-30990.md) 🔴 ✅

**名称:** CVE-2023-30990 - IBM i DDM 远程命令执行  
**类型:** 远程命令执行 (RCE)  
**风险:** 高危，可远程执行CL命令  
**投毒风险:** 1%  
**发现时间:** 2025-09-04  
**POC仓库:** [CVE-2023-30990](https://github.com/silentsignal/CVE-2023-30990)  

---

### [CVE-2021-23017](CVE-2021-23017-6lj_EVIL-CVE-2021-23017-Update-2025.md) 🔴 ✅

**名称:** CVE-2021-23017-Nginx Resolver 内存覆盖  
**类型:** 内存覆盖  
**风险:** 高危，可能导致worker进程崩溃或潜在的其他影响  
**投毒风险:** 10%  
**发现时间:** 2025-09-04  
**POC仓库:** [EVIL-CVE-2021-23017-Update-2025](https://github.com/6lj/EVIL-CVE-2021-23017-Update-2025)  

---

### [CVE-2024-21182](CVE-2024-21182-kursadalsan_CVE-2024-21182.md) 🔴 ✅

**名称:** CVE-2024-21182-Oracle WebLogic Server JNDI 注入  
**类型:** JNDI注入  
**风险:** 高危，可能导致未经授权访问敏感数据或完全控制 Oracle WebLogic Server  
**投毒风险:** 0%  
**发现时间:** 2025-09-04  
**POC仓库:** [CVE-2024-21182](https://github.com/kursadalsan/CVE-2024-21182)  

---

### [CVE-2024-21182](CVE-2024-21182-k4it0k1d_CVE-2024-21182.md) 🔴 ✅

**名称:** CVE-2024-21182 - Oracle WebLogic Server JNDI注入  
**类型:** JNDI注入  
**风险:** 高危，可能导致未授权访问敏感数据  
**投毒风险:** 0%  
**发现时间:** 2025-09-04  
**POC仓库:** [CVE-2024-21182](https://github.com/k4it0k1d/CVE-2024-21182)  

---

### [CVE-2025-54988](CVE-2025-54988-mgthuramoemyint_POC-CVE-2025-54988.md) 🔴 ✅

**名称:** CVE-2025-54988 - Apache Tika PDF parser module XXE  
**类型:** XML 外部实体注入 (XXE)  
**风险:** 高危，可能导致敏感数据泄露、访问内部资源、触发第三方服务器恶意请求。  
**投毒风险:** 10%  
**发现时间:** 2025-09-04  
**POC仓库:** [POC-CVE-2025-54988](https://github.com/mgthuramoemyint/POC-CVE-2025-54988)  

---

### [CVE-2025-57819](CVE-2025-57819-ImBIOS_lab-cve-2025-57819.md)  ✅

**名称:** CVE-2025-57819-FreePBX-SQL注入  
**类型:** SQL注入  
**风险:** 严重，可能导致未授权访问、数据库操纵和远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-09-04  
**POC仓库:** [lab-cve-2025-57819](https://github.com/ImBIOS/lab-cve-2025-57819)  

---

### [CVE-2025-32709](CVE-2025-32709-AdnanSiyat_How-to-Patch-CVE-2025-32709.md) 🔴 

**名称:** CVE-2025-32709 Windows Ancillary Function Driver for WinSock Use-After-Free 提权漏洞  
**类型:** Use-After-Free  
**风险:** 高危，允许本地授权的攻击者提升权限  
**投毒风险:** 5%  
**发现时间:** 2025-09-04  
**POC仓库:** [How-to-Patch-CVE-2025-32709](https://github.com/AdnanSiyat/How-to-Patch-CVE-2025-32709)  

---

### [CVE-2025-6085](CVE-2025-6085-d0n601_CVE-2025-6085.md) 🔴 ✅

**名称:** Make Connector <= 1.5.10 - Authenticated (Admin+) Arbitrary File Upload  
**类型:** 任意文件上传  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-09-04  
**POC仓库:** [CVE-2025-6085](https://github.com/d0n601/CVE-2025-6085)  

---

### [CVE-2025-24893](CVE-2025-24893-b0ySie7e_CVE-2025-24893.md) 🔴 ✅

**名称:** CVE-2025-24893-XWiki-RCE  
**类型:** 远程代码执行  
**风险:** 高危，允许未经身份验证的远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-09-03  
**POC仓库:** [CVE-2025-24893](https://github.com/b0ySie7e/CVE-2025-24893)  

---

### [CVE-2025-44228](CVE-2025-44228-Reeadmon_Lnk-Exploit-FileBinder-Certificate-Spoofer-Reg-Doc-Cve-Rce.md) 🔴 ✅

**名称:** CVE-2025-44228 / CVE-2021-44228 LNK Exploit  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致远程代码执行和系统完全控制  
**投毒风险:** 60%  
**发现时间:** 2025-09-03  
**POC仓库:** [Lnk-Exploit-FileBinder-Certificate-Spoofer-Reg-Doc-Cve-Rce](https://github.com/Reeadmon/Lnk-Exploit-FileBinder-Certificate-Spoofer-Reg-Doc-Cve-Rce)  

---

### [CVE-2025-44228](CVE-2025-44228-Reeadmon_Office-Exploit-Cve2025-Xml-Doc-Docx-Rce-Builder-Fud.md) 🔴 ✅

**名称:** CVE-2025-44228 / CVE-2025-4428 Office宏代码远程代码执行漏洞  
**类型:** 远程代码执行  
**风险:** 高危，允许攻击者在目标系统上执行任意代码  
**投毒风险:** 5%  
**发现时间:** 2025-09-03  
**POC仓库:** [Office-Exploit-Cve2025-Xml-Doc-Docx-Rce-Builder-Fud](https://github.com/Reeadmon/Office-Exploit-Cve2025-Xml-Doc-Docx-Rce-Builder-Fud)  

---

### [CVE-2025-9074](CVE-2025-9074-j3r1ch0123_CVE-2025-9074.md) 🔴 ✅

**名称:** CVE-2025-9074 - Docker Desktop 远程 API 未授权访问  
**类型:** 未授权访问  
**风险:** 高危，可能导致容器逃逸、主机控制  
**投毒风险:** 10%  
**发现时间:** 2025-09-03  
**POC仓库:** [CVE-2025-9074](https://github.com/j3r1ch0123/CVE-2025-9074)  

---

### [CVE-2025-43300](CVE-2025-43300-PwnToday_CVE-2025-43300.md) 🔴 ✅

**名称:** CVE-2025-43300-ImageIO-OOB写入  
**类型:** 越界写入  
**风险:** 高危，可能导致内存损坏和远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-09-03  
**POC仓库:** [CVE-2025-43300](https://github.com/PwnToday/CVE-2025-43300)  

---

### [CVE-2025-55998](CVE-2025-55998-Ocmenog_CVE-2025-55998.md)  ✅

**名称:** CVE-2025-55998  
**类型:** 未知  
**风险:** 未知  
**投毒风险:** 10%  
**发现时间:** 2025-09-03  
**POC仓库:** [CVE-2025-55998](https://github.com/Ocmenog/CVE-2025-55998)  

---

### [CVE-2025-2082](CVE-2025-2082-shirabo_cve-2025-2082-POV.md) 🔴 ✅

**名称:** CVE-2025-2082 Tesla Model 3 VCSEC 整数溢出远程代码执行漏洞  
**类型:** 整数溢出导致远程代码执行  
**风险:** 高危，可能导致车辆控制权限被获取  
**投毒风险:** 5%  
**发现时间:** 2025-09-03  
**POC仓库:** [cve-2025-2082-POV](https://github.com/shirabo/cve-2025-2082-POV)  

---

### [CVE-2025-22131](CVE-2025-22131-ZzN1NJ4_CVE-2025-22131-PoC.md) 🟡 ✅

**名称:** CVE-2025-22131-PhpSpreadsheet-XSS  
**类型:** 跨站脚本 (XSS)  
**风险:** 中危，可能导致cookie泄露和权限提升  
**投毒风险:** 10%  
**发现时间:** 2025-09-03  
**POC仓库:** [CVE-2025-22131-PoC](https://github.com/ZzN1NJ4/CVE-2025-22131-PoC)  

---

### [CVE-2025-27591](CVE-2025-27591-danil-koltsov_below-log-race-poc.md) 🔴 ✅

**名称:** CVE-2025-27591-below-权限提升  
**类型:** 权限提升  
**风险:** 高危，本地用户可以获得root权限  
**投毒风险:** 0%  
**发现时间:** 2025-09-03  
**POC仓库:** [below-log-race-poc](https://github.com/danil-koltsov/below-log-race-poc)  

---

### [CVE-2025-27591](CVE-2025-27591-HOEUN-Visai_CVE-2025-27591-below-.md) 🔴 ✅

**名称:** CVE-2025-27591-below-权限提升漏洞  
**类型:** 权限提升  
**风险:** 高危，允许本地普通用户提升至root权限  
**投毒风险:** 0%  
**发现时间:** 2025-09-03  
**POC仓库:** [CVE-2025-27591-below-](https://github.com/HOEUN-Visai/CVE-2025-27591-below-)  

---

### [CVE-2025-5252](CVE-2025-5252-aydin5245_CVE-2025-5252-CVE-ivanti.md) 🔴 ✅

**名称:** CVE-2025-5252-PHPGurukul News Portal Project-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露、权限提升和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-09-03  
**POC仓库:** [CVE-2025-5252-CVE-ivanti](https://github.com/aydin5245/CVE-2025-5252-CVE-ivanti)  

---

### [CVE-2025-24813](CVE-2025-24813-drcrypterdotru_Apache-GOExploiter.md) 🔴 ✅

**名称:** CVE-2025-24813-Apache Tomcat-路径等价漏洞/反序列化漏洞  
**类型:** 路径等价漏洞/反序列化漏洞  
**风险:** 高危，可能导致远程代码执行和/或信息泄露和/或信息篡改  
**投毒风险:** 1%  
**发现时间:** 2025-09-03  
**POC仓库:** [Apache-GOExploiter](https://github.com/drcrypterdotru/Apache-GOExploiter)  

---

### [CVE-2025-24813](CVE-2025-24813-Olabanji10_Apache-GOExploiter.md) 🔴 ✅

**名称:** CVE-2025-24813  
**类型:** 路径等价/反序列化  
**风险:** 高危，可能导致远程代码执行或信息泄露  
**投毒风险:** 5%  
**发现时间:** 2025-09-03  
**POC仓库:** [Apache-GOExploiter](https://github.com/Olabanji10/Apache-GOExploiter)  

---

### [CVE-2025-6019](CVE-2025-6019-harshitvarma05_CVE-2025-6019.md) 🔴 ✅

**名称:** CVE-2025-6019-libblockdev-LPE  
**类型:** 本地权限提升  
**风险:** 高危，允许低权限用户获取root权限  
**投毒风险:** 10%  
**发现时间:** 2025-09-03  
**POC仓库:** [CVE-2025-6019](https://github.com/harshitvarma05/CVE-2025-6019)  

---

### [CVE-2017-6074](CVE-2017-6074-BimsaraMalinda_Linux-Kernel-4.4.0-Ubuntu---DCCP-Double-Free-Privilege-Escalation-CVE-2017-6074.md) 🔴 ✅

**名称:** CVE-2017-6074-Linux Kernel DCCP Double-Free  
**类型:** Double-Free  
**风险:** 高危，本地用户可提升至root权限或导致拒绝服务  
**投毒风险:** 5%  
**发现时间:** 2025-09-03  
**POC仓库:** [Linux-Kernel-4.4.0-Ubuntu---DCCP-Double-Free-Privilege-Escalation-CVE-2017-6074](https://github.com/BimsaraMalinda/Linux-Kernel-4.4.0-Ubuntu---DCCP-Double-Free-Privilege-Escalation-CVE-2017-6074)  

---

### [CVE-2017-6074](CVE-2017-6074-toanthang1842002_CVE-2017-6074.md) 🔴 ✅

**名称:** CVE-2017-6074 - Linux Kernel DCCP Double-Free  
**类型:** Double-Free  
**风险:** 高危，本地用户可提升权限至root或导致拒绝服务  
**投毒风险:** 10%  
**发现时间:** 2025-09-03  
**POC仓库:** [CVE-2017-6074](https://github.com/toanthang1842002/CVE-2017-6074)  

---

### [CVE-2017-6074](CVE-2017-6074-34zY_CVE-2017-6074-DOS.md) 🔴 ✅

**名称:** CVE-2017-6074 - Linux DCCP Double-Free  
**类型:** Double-Free  
**风险:** 高危，可导致本地提权或拒绝服务  
**投毒风险:** 10%  
**发现时间:** 2025-09-03  
**POC仓库:** [CVE-2017-6074-DOS](https://github.com/34zY/CVE-2017-6074-DOS)  

---

### [CVE-2015-1328](CVE-2015-1328-elit3pwner_CVE-2015-1328-GoldenEye.md) 🔴 ✅

**名称:** CVE-2015-1328 - Ubuntu Overlayfs 本地提权漏洞  
**类型:** 本地提权  
**风险:** 高危，允许本地用户获取root权限  
**投毒风险:** 10%  
**发现时间:** 2025-09-03  
**POC仓库:** [CVE-2015-1328-GoldenEye](https://github.com/elit3pwner/CVE-2015-1328-GoldenEye)  

---

### [CVE-2025-56803](CVE-2025-56803-shinyColumn_CVE-2025-56803.md) 🔴 ✅

**名称:** CVE-2025-56803-Figma-命令注入  
**类型:** 命令注入  
**风险:** 高危，可能导致任意代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-09-03  
**POC仓库:** [CVE-2025-56803](https://github.com/shinyColumn/CVE-2025-56803)  

---

### [CVE-2025-3515](CVE-2025-3515-ImBIOS_lab-cve-2025-3515.md) 🔴 ✅

**名称:** CVE-2025-3515 Drag and Drop Multiple File Upload for Contact Form 7 - 任意文件上传  
**类型:** 任意文件上传  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-09-03  
**POC仓库:** [lab-cve-2025-3515](https://github.com/ImBIOS/lab-cve-2025-3515)  

---

### [CVE-2025-12654](CVE-2025-12654-Maitonnx_Anydesk-Exploit-CVE-2025-12654-RCE-Builder.md) 🔴 ✅

**名称:** CVE-2025-12654-AnyDesk-远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，允许攻击者在目标系统上执行任意代码  
**投毒风险:** 75%  
**发现时间:** 2025-09-03  
**POC仓库:** [Anydesk-Exploit-CVE-2025-12654-RCE-Builder](https://github.com/Maitonnx/Anydesk-Exploit-CVE-2025-12654-RCE-Builder)  

---

### [CVE-2023-26563](CVE-2023-26563-RupturaInfoSec_CVE-2023-26563-26564-26565.md) 🔴 ✅

**名称:** CVE-2023-26563 - Syncfusion EJ2 Node File Provider Directory Traversal  
**类型:** 目录遍历  
**风险:** 高危，未经身份验证的攻击者可以读取/删除/上传服务器上可访问的任何文件。  
**投毒风险:** 10%  
**发现时间:** 2025-09-03  
**POC仓库:** [CVE-2023-26563-26564-26565](https://github.com/RupturaInfoSec/CVE-2023-26563-26564-26565)  

---

### [CVE-2016-15042](CVE-2016-15042-ImBIOS_lab-cve-2016-15042.md) 🔴 ✅

**名称:** CVE-2016-15042 - WordPress Frontend File Manager & N-Media Post Front-end Form Unauthenticated File Upload  
**类型:** 任意文件上传  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-09-03  
**POC仓库:** [lab-cve-2016-15042](https://github.com/ImBIOS/lab-cve-2016-15042)  

---

### [CVE-2015-1328](CVE-2015-1328-YastrebX_CVE-2015-1328.md) 🔴 ✅

**名称:** CVE-2015-1328 - Overlayfs 本地提权  
**类型:** 本地提权  
**风险:** 高危，本地用户可提升至root权限  
**投毒风险:** 0%  
**发现时间:** 2025-09-03  
**POC仓库:** [CVE-2015-1328](https://github.com/YastrebX/CVE-2015-1328)  

---

### [CVE-2015-1328](CVE-2015-1328-devtz007_overlayfs_CVE-2015-1328.md) 🔴 ✅

**名称:** CVE-2015-1328 - Overlayfs 本地提权  
**类型:** 权限提升  
**风险:** 高危，本地用户可获取 root 权限  
**投毒风险:** 1%  
**发现时间:** 2025-09-03  
**POC仓库:** [overlayfs_CVE-2015-1328](https://github.com/devtz007/overlayfs_CVE-2015-1328)  

---

### [CVE-2015-1328](CVE-2015-1328-1mgR00T_CVE-2015-1328.md) 🔴 ✅

**名称:** CVE-2015-1328 - OverlayFS 本地提权  
**类型:** 本地提权  
**风险:** 高危，允许本地用户获取root权限  
**投毒风险:** 10%  
**发现时间:** 2025-09-03  
**POC仓库:** [CVE-2015-1328](https://github.com/1mgR00T/CVE-2015-1328)  

---

### [CVE-2020-0610](CVE-2020-0610-ImBIOS_lab-cve-2020-0610.md) 🔴 ✅

**名称:** CVE-2020-0610 Windows Remote Desktop Gateway (RD Gateway) 远程代码执行漏洞  
**类型:** 远程代码执行  
**风险:** 高危，允许未经身份验证的攻击者执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-09-03  
**POC仓库:** [lab-cve-2020-0610](https://github.com/ImBIOS/lab-cve-2020-0610)  

---

### [CVE-2025-56435](CVE-2025-56435-Jingyi-u_-CVE-2025-56435.md) 🔴 ✅

**名称:** CVE-2025-56435  
**类型:** 目录遍历/SQL注入  
**风险:** 高危，可能导致数据库被篡改，服务器被控制  
**投毒风险:** 10%  
**发现时间:** 2025-09-03  
**POC仓库:** [-CVE-2025-56435](https://github.com/Jingyi-u/-CVE-2025-56435)  

---

### [CVE-2025-27480](CVE-2025-27480-mrk336_CVE-2025-27480.md) 🔴 ✅

**名称:** CVE-2025-27480-Windows Remote Desktop Services-Use After Free  
**类型:** Use After Free  
**风险:** 高危，允许未经授权的攻击者通过网络执行代码  
**投毒风险:** 10%  
**发现时间:** 2025-09-03  
**POC仓库:** [CVE-2025-27480](https://github.com/mrk336/CVE-2025-27480)  

---

### [CVE-2025-45805](CVE-2025-45805-mhsinj_CVE-2025-45805.md) 🔴 ✅

**名称:** CVE-2025-45805  
**类型:** 存储型跨站脚本 (Stored XSS)  
**风险:** 高危，可能导致账户接管、会话劫持、cookie 窃取  
**投毒风险:** 10%  
**发现时间:** 2025-09-02  
**POC仓库:** [CVE-2025-45805](https://github.com/mhsinj/CVE-2025-45805)  

---

### [CVE-2025-9491](CVE-2025-9491-barbaraeivyu_CVE-2025-9491.md) 🔴 ✅

**名称:** CVE-2025-9491 Microsoft Windows LNK File UI Misrepresentation Remote Code Execution Vulnerability  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行，完全控制受害者系统  
**投毒风险:** 10%  
**发现时间:** 2025-09-02  
**POC仓库:** [CVE-2025-9491](https://github.com/barbaraeivyu/CVE-2025-9491)  

---

### [CVE-2025-9784](CVE-2025-9784-drackyjr_CVE-2025-9784.md) 🔴 ✅

**名称:** CVE-2025-9784 MadeYouReset HTTP/2 DoS  
**类型:** 拒绝服务 (DoS)  
**风险:** 高危，可能导致服务中断  
**投毒风险:** 5%  
**发现时间:** 2025-09-02  
**POC仓库:** [CVE-2025-9784](https://github.com/drackyjr/CVE-2025-9784)  

---

### [CVE-2024-47875](CVE-2024-47875-roj1py_CVE-2024-47875-PhpSpreadsheet-XSS-PoC.md) 🔴 ✅

**名称:** CVE-2024-47875-PhpSpreadsheet-XSS  
**类型:** 跨站脚本攻击(XSS)  
**风险:** 高危，可能导致用户信息泄露、会话劫持和恶意代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-09-02  
**POC仓库:** [CVE-2024-47875-PhpSpreadsheet-XSS-PoC](https://github.com/roj1py/CVE-2024-47875-PhpSpreadsheet-XSS-PoC)  

---

### [CVE-2025-7775](CVE-2025-7775-mr-r3b00t_CVE-2025-7775.md) 🔴 

**名称:** CVE-2025-7775-NetScaler-内存溢出  
**类型:** 内存溢出  
**风险:** 高危，可能导致远程代码执行或拒绝服务  
**投毒风险:** 0%  
**发现时间:** 2025-09-02  
**POC仓库:** [CVE-2025-7775](https://github.com/mr-r3b00t/CVE-2025-7775)  

---

### [CVE-2025-23266](CVE-2025-23266-r0binak_CVE-2025-23266.md) 🔴 ✅

**名称:** CVE-2025-23266-NVIDIA Container Toolkit-容器逃逸  
**类型:** 容器逃逸  
**风险:** 高危，可能导致权限提升、数据篡改、信息泄露和拒绝服务  
**投毒风险:** 10%  
**发现时间:** 2025-09-02  
**POC仓库:** [CVE-2025-23266](https://github.com/r0binak/CVE-2025-23266)  

---

### [CVE-2017-11882](CVE-2017-11882-futureFfff_CVE-2017.md) 🔴 ✅

**名称:** CVE-2017-11882-Microsoft Office 内存破坏漏洞  
**类型:** 远程代码执行  
**风险:** 高危，允许攻击者在当前用户上下文中执行任意代码  
**投毒风险:** 90%  
**发现时间:** 2025-09-02  
**POC仓库:** [CVE-2017](https://github.com/futureFfff/CVE-2017)  

---

### [CVE-2024-53677](CVE-2024-53677-Cythonic1_CVE-2024-53677-POC.md) 🔴 ✅

**名称:** CVE-2024-53677-Apache Struts 文件上传路径遍历导致RCE  
**类型:** 文件上传漏洞,路径遍历,远程代码执行  
**风险:** 高危，可能导致远程代码执行和服务器控制  
**投毒风险:** 10%  
**发现时间:** 2025-09-02  
**POC仓库:** [CVE-2024-53677-POC](https://github.com/Cythonic1/CVE-2024-53677-POC)  

---

### [CVE-2025-6934](CVE-2025-6934-Pwdnx1337_CVE-2025-6934.md) 🔴 ✅

**名称:** CVE-2025-6934-Opal Estate Pro-未授权提权  
**类型:** 未授权提权  
**风险:** 高危，允许未经身份验证的攻击者创建管理员帐户并完全控制 WordPress 站点。  
**投毒风险:** 5%  
**发现时间:** 2025-09-02  
**POC仓库:** [CVE-2025-6934](https://github.com/Pwdnx1337/CVE-2025-6934)  

---

### [CVE-2024-51568](CVE-2024-51568-jsnv-dev_CVE-2024-51568---CyberPanel-Command-Injection-Nuclei-Template.md) 🔴 ✅

**名称:** CVE-2024-51568 - CyberPanel Pre-Authentication Command Injection  
**类型:** 命令注入  
**风险:** 高危，允许未经身份验证的远程攻击者以root权限执行任意命令。  
**投毒风险:** 5%  
**发现时间:** 2025-09-02  
**POC仓库:** [CVE-2024-51568---CyberPanel-Command-Injection-Nuclei-Template](https://github.com/jsnv-dev/CVE-2024-51568---CyberPanel-Command-Injection-Nuclei-Template)  

---

### [CVE-2024-45590](CVE-2024-45590-dhruvik-git_CVE-2024-45590.md) 🔴 ✅

**名称:** CVE-2024-45590-body-parser-DoS  
**类型:** 拒绝服务 (DoS)  
**风险:** 高危，可能导致服务中断  
**投毒风险:** 0%  
**发现时间:** 2025-09-02  
**POC仓库:** [CVE-2024-45590](https://github.com/dhruvik-git/CVE-2024-45590)  

---

### [CVE-2023-22515](CVE-2023-22515-killvxk_CVE-2023-22515-joaoviictorti.md)  ✅

**名称:** CVE-2023-22515-Atlassian Confluence-Broken Access Control  
**类型:** Broken Access Control  
**风险:** 严重，可能导致未经授权的管理员帐户创建和远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-09-02  
**POC仓库:** [CVE-2023-22515-joaoviictorti](https://github.com/killvxk/CVE-2023-22515-joaoviictorti)  

---

### [CVE-2021-41617](CVE-2021-41617-AdnanApriliyansyahh_CVE-2021-41617.md) 🟡 ✅

**名称:** CVE-2021-41617-OpenSSH-权限提升  
**类型:** 权限提升  
**风险:** 中危，可能导致低权限用户提升至sshd进程的权限  
**投毒风险:** 5%  
**发现时间:** 2025-09-02  
**POC仓库:** [CVE-2021-41617](https://github.com/AdnanApriliyansyahh/CVE-2021-41617)  

---

### [CVE-2022-1592](CVE-2022-1592-AdnanApriliyansyahh_CVE-2022-1592.md) 🔴 ✅

**名称:** CVE-2022-1592 - clinical-genomics/scout SSRF  
**类型:** 服务器端请求伪造 (SSRF)  
**风险:** 高危，可能导致敏感信息泄露、内部服务访问和潜在的XSS  
**投毒风险:** 0%  
**发现时间:** 2025-09-02  
**POC仓库:** [CVE-2022-1592](https://github.com/AdnanApriliyansyahh/CVE-2022-1592)  

---

### [CVE-2025-57819](CVE-2025-57819-net-hex_CVE-2025-57819.md)  ✅

**名称:** CVE-2025-57819-FreePBX-身份验证绕过SQL注入RCE  
**类型:** 身份验证绕过, SQL注入, 远程代码执行  
**风险:** 严重，未经身份验证的攻击者可以完全控制受影响的FreePBX系统，导致数据泄露、篡改和系统不可用，甚至控制整个PBX网络。  
**投毒风险:** 10%  
**发现时间:** 2025-09-02  
**POC仓库:** [CVE-2025-57819](https://github.com/net-hex/CVE-2025-57819)  

---

### [CVE-2019-10945](CVE-2019-10945-dpgg101_CVE-2019-10945.md) 🔴 ✅

**名称:** CVE-2019-10945-Joomla-目录遍历/任意文件删除  
**类型:** 目录遍历/任意文件删除  
**风险:** 高危，可能导致信息泄露和服务器被控制  
**投毒风险:** 10%  
**发现时间:** 2025-09-02  
**POC仓库:** [CVE-2019-10945](https://github.com/dpgg101/CVE-2019-10945)  

---

### [CVE-2019-10945](CVE-2019-10945-Snizi_CVE-2019-10945.md) 🔴 ✅

**名称:** CVE-2019-10945-Joomla-目录遍历和任意文件删除  
**类型:** 目录遍历和任意文件删除  
**风险:** 高危，可能导致服务器文件泄露和被恶意删除  
**投毒风险:** 10%  
**发现时间:** 2025-09-02  
**POC仓库:** [CVE-2019-10945](https://github.com/Snizi/CVE-2019-10945)  

---

### [CVE-2017-9841](CVE-2017-9841-Habibullah1101_PHPUnit-GoScan.md) 🔴 ✅

**名称:** CVE-2017-9841 PHPUnit 远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，允许攻击者执行任意PHP代码  
**投毒风险:** 0%  
**发现时间:** 2025-09-01  
**POC仓库:** [PHPUnit-GoScan](https://github.com/Habibullah1101/PHPUnit-GoScan)  

---

### [CVE-2025-57819](CVE-2025-57819-blueisbeautiful_CVE-2025-57819.md)  ✅

**名称:** CVE-2025-57819-FreePBX-SQL注入和RCE  
**类型:** SQL注入和远程代码执行  
**风险:** 严重，允许未经身份验证的远程代码执行和数据库操控  
**投毒风险:** 10%  
**发现时间:** 2025-09-01  
**POC仓库:** [CVE-2025-57819](https://github.com/blueisbeautiful/CVE-2025-57819)  

---

### [CVE-2024-36886](CVE-2024-36886-abubakar-shahid_CVE-2024-36886.md) 🔴 

**名称:** CVE-2024-36886  
**类型:** UAF（Use-After-Free）  
**风险:** 高危，可能导致敏感信息泄露、数据篡改或拒绝服务，甚至远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-09-01  
**POC仓库:** [CVE-2024-36886](https://github.com/abubakar-shahid/CVE-2024-36886)  

---

### [CVE-2024-25765](CVE-2024-25765-dennismendes10_CMD-Exploit-CVE-2024-RCE-AboRady-FUD-25765-Injection.md) 🔴 ✅

**名称:** CVE-2024-RCE-AboRady-FUD-25765-Injection  
**类型:** 命令注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 85%  
**发现时间:** 2025-09-01  
**POC仓库:** [CMD-Exploit-CVE-2024-RCE-AboRady-FUD-25765-Injection](https://github.com/dennismendes10/CMD-Exploit-CVE-2024-RCE-AboRady-FUD-25765-Injection)  

---

### [CVE-2025-3515](CVE-2025-3515-blueisbeautiful_CVE-2025-3515.md) 🔴 ✅

**名称:** CVE-2025-3515 - Drag and Drop Multiple File Upload for Contact Form 7 - 任意文件上传导致RCE  
**类型:** 任意文件上传  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-09-01  
**POC仓库:** [CVE-2025-3515](https://github.com/blueisbeautiful/CVE-2025-3515)  

---

### [CVE-2025-53691](CVE-2025-53691-blueisbeautiful_CVE-2025-53691.md) 🔴 ✅

**名称:** CVE-2025-53691 - Sitecore Experience Platform - RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-09-01  
**POC仓库:** [CVE-2025-53691](https://github.com/blueisbeautiful/CVE-2025-53691)  

---

### [CVE-2025-53694](CVE-2025-53694-blueisbeautiful_CVE-2025-53694.md) 🟡 ✅

**名称:** CVE-2025-53694 Sitecore 信息泄露  
**类型:** 信息泄露  
**风险:** 中危，可能导致敏感信息泄露，为进一步攻击提供信息  
**投毒风险:** 0%  
**发现时间:** 2025-09-01  
**POC仓库:** [CVE-2025-53694](https://github.com/blueisbeautiful/CVE-2025-53694)  

---

### [CVE-2025-53694](CVE-2025-53694-blueisbeautiful_CVE-2025-53694-to-CVE-2025-53691.md) 🔴 ✅

**名称:** Sitecore Experience Platform CVE-2025-53691/53693/53694 漏洞利用链  
**类型:** 远程代码执行 (RCE), 缓存投毒, 信息泄露  
**风险:** 高危，允许未经身份验证的攻击者执行远程代码，控制服务器  
**投毒风险:** 10%  
**发现时间:** 2025-09-01  
**POC仓库:** [CVE-2025-53694-to-CVE-2025-53691](https://github.com/blueisbeautiful/CVE-2025-53694-to-CVE-2025-53691)  

---

### [CVE-2025-34300](CVE-2025-34300-jisi-001_CVE-2025-34300POC.md) 🔴 ✅

**名称:** CVE-2025-34300-Sawtooth Lighthouse Studio-模板注入  
**类型:** 模板注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-09-01  
**POC仓库:** [CVE-2025-34300POC](https://github.com/jisi-001/CVE-2025-34300POC)  

---

### [CVE-2025-53693](CVE-2025-53693-blueisbeautiful_CVE-2025-53693.md) 🔴 ✅

**名称:** CVE-2025-53693-Sitecore-HTML Cache Poisoning  
**类型:** HTML Cache Poisoning  
**风险:** 高危，可能导致XSS、信息泄露、重定向等攻击  
**投毒风险:** 0%  
**发现时间:** 2025-09-01  
**POC仓库:** [CVE-2025-53693](https://github.com/blueisbeautiful/CVE-2025-53693)  

---

### [CVE-2017-9841](CVE-2017-9841-joelindra_Argus.md) 🔴 ✅

**名称:** CVE-2017-9841-PHPUnit-RCE  
**类型:** 远程代码执行(RCE)  
**风险:** 高危，可完全控制服务器  
**投毒风险:** 10%  
**发现时间:** 2025-09-01  
**POC仓库:** [Argus](https://github.com/joelindra/Argus)  

---

### [CVE-2017-9841](CVE-2017-9841-drcrypterdotru_PHPUnit-GoScan.md) 🔴 ✅

**名称:** CVE-2017-9841 PHPUnit远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可导致服务器完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-09-01  
**POC仓库:** [PHPUnit-GoScan](https://github.com/drcrypterdotru/PHPUnit-GoScan)  

---

### [CVE-2017-9841](CVE-2017-9841-Pwdnx1337_CVE-2017-9841.md) 🔴 ✅

**名称:** CVE-2017-9841-PHPUnit-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，允许攻击者执行任意PHP代码  
**投毒风险:** 0%  
**发现时间:** 2025-09-01  
**POC仓库:** [CVE-2017-9841](https://github.com/Pwdnx1337/CVE-2017-9841)  

---

### [CVE-2018-19207](CVE-2018-19207-aeroot_WP-GDPR-Compliance-Plugin-Exploit.md) 🔴 ✅

**名称:** CVE-2018-19207 - WP GDPR Compliance Plugin - 权限提升/代码执行  
**类型:** 权限提升/代码执行  
**风险:** 高危，允许未授权用户执行任意代码和提升权限  
**投毒风险:** 1%  
**发现时间:** 2025-09-01  
**POC仓库:** [WP-GDPR-Compliance-Plugin-Exploit](https://github.com/aeroot/WP-GDPR-Compliance-Plugin-Exploit)  

---

### [CVE-2018-19207](CVE-2018-19207-cved-sources_cve-2018-19207.md) 🔴 ✅

**名称:** CVE-2018-19207-WP GDPR Compliance-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-09-01  
**POC仓库:** [cve-2018-19207](https://github.com/cved-sources/cve-2018-19207)  

---

### [CVE-2018-19207](CVE-2018-19207-Pwdnx1337_CVE-2018-19207.md) 🔴 ✅

**名称:** CVE-2018-19207-WP GDPR Compliance-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，允许未授权用户修改管理员邮箱，可能导致权限提升和进一步的攻击  
**投毒风险:** 0%  
**发现时间:** 2025-09-01  
**POC仓库:** [CVE-2018-19207](https://github.com/Pwdnx1337/CVE-2018-19207)  

---

### [CVE-2025-27480](CVE-2025-27480-mrk336_CVE-2025-27480-The-Silent-Gateway-Risk.md) 🔴 

**名称:** CVE-2025-27480 Windows Remote Desktop Services RCE  
**类型:** 远程代码执行  
**风险:** 高危，未经授权的攻击者可以通过网络执行任意代码  
**投毒风险:** 0%  
**发现时间:** 2025-09-01  
**POC仓库:** [CVE-2025-27480-The-Silent-Gateway-Risk](https://github.com/mrk336/CVE-2025-27480-The-Silent-Gateway-Risk)  

---

### [CVE-2021-3456](CVE-2021-3456-mrk336_CVE-2021-3456.md) 🔴 ✅

**名称:** CVE-2021-3456 - Foreman smart_proxy_salt 权限绕过  
**类型:** 权限绕过/不当授权  
**风险:** 高危，可能导致资源删除和拒绝服务  
**投毒风险:** 10%  
**发现时间:** 2025-09-01  
**POC仓库:** [CVE-2021-3456](https://github.com/mrk336/CVE-2021-3456)  

---

### [CVE-2025-50565](CVE-2025-50565-OoO7ce_CVE-2025-50565.md) 🔴 ✅

**名称:** CVE-2025-50565-DouboERP-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-09-01  
**POC仓库:** [CVE-2025-50565](https://github.com/OoO7ce/CVE-2025-50565)  

---


## 🔍 快速查找

- [按CVE编号查找](../../by-cve/)
- [返回2025年总览](../README.md)
- [返回总索引](../../README.md)

---

*本文档由 VulnWatchdog 自动生成 @ 2025-11-26 13:32*
