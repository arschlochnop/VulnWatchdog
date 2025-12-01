# 2020年CVE漏洞情报汇总

> 📅 CVE年份: **2020**
> 📊 漏洞总数: **377** 个
> 🔥 高危漏洞: **349** 个 (92.6%)
> ⚠️ 高投毒风险: **5** 个

---

## 📊 漏洞类型分布

| 类型 | 数量 | 占比 |
|------|------|------|
| 远程代码执行 | 111 | 29.4% |
| 远程代码执行 (RCE) | 66 | 17.5% |
| 目录遍历 | 28 | 7.4% |
| 权限提升 | 28 | 7.4% |
| 路径遍历 | 14 | 3.7% |
| 反序列化漏洞 | 13 | 3.4% |
| 特权提升 | 9 | 2.4% |
| 命令注入 | 7 | 1.9% |
| 认证绕过/远程代码执行 | 7 | 1.9% |
| JavaEL注入 | 6 | 1.6% |

---

## 🔍 漏洞详情列表

### [CVE-2020-9922](CVE-2020-9922-Wowfunhappy_Fix-Apple-Mail-CVE-2020-9922.md) 🔴

**名称:** CVE-2020-9922 - macOS Mail 任意文件写入
**类型:** 任意文件写入 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [Fix-Apple-Mail-CVE-2020-9922](https://github.com/Wowfunhappy/Fix-Apple-Mail-CVE-2020-9922)

### [CVE-2020-9547](CVE-2020-9547-Pranjal6955_CVE-2020-9547.md) 🔴

**名称:** CVE-2020-9547-jackson-databind反序列化RCE
**类型:** 反序列化远程代码执行 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [CVE-2020-9547](https://github.com/Pranjal6955/CVE-2020-9547)

### [CVE-2020-9547](CVE-2020-9547-fairyming_CVE-2020-9547.md) 🔴

**名称:** CVE-2020-9547：FasterXML jackson-databind 远程代码执行漏洞
**类型:** 反序列化漏洞 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [CVE-2020-9547](https://github.com/fairyming/CVE-2020-9547)

### [CVE-2020-9488](CVE-2020-9488-arsalanraja987_java-log4j-cve-2020-9488.md)

**名称:** CVE-2020-9488 - Apache Log4j SMTP Appender证书验证绕过
**类型:** 中间人攻击 (Man-in-the-Middle) | **POC:** 是 | **投毒风险:** 10%
**仓库:** [java-log4j-cve-2020-9488](https://github.com/arsalanraja987/java-log4j-cve-2020-9488)

### [CVE-2020-9483](CVE-2020-9483-tuaandatt_CVE-2020-9483---Apache-Skywalking-8.3.0.md) 🔴

**名称:** CVE-2020-9483 - Apache SkyWalking SQL注入
**类型:** SQL注入 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [CVE-2020-9483---Apache-Skywalking-8.3.0](https://github.com/tuaandatt/CVE-2020-9483---Apache-Skywalking-8.3.0)

### [CVE-2020-9483](CVE-2020-9483-shanika04_apache_skywalking.md) 🔴

**名称:** CVE-2020-9483-Apache SkyWalking-SQL注入
**类型:** SQL注入 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [apache_skywalking](https://github.com/shanika04/apache_skywalking)

### [CVE-2020-9483](CVE-2020-9483-Neko-chanQwQ_CVE-2020-9483.md) 🔴

**名称:** CVE-2020-9483-Apache SkyWalking-SQL注入
**类型:** SQL注入 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [CVE-2020-9483](https://github.com/Neko-chanQwQ/CVE-2020-9483)

### [CVE-2020-8570](CVE-2020-8570-shoucheng3_kubernetes-client__java_CVE-2020-8570_client-java-parent-9_0_2_fixed.md) 🔴

**名称:** CVE-2020-8570 Kubernetes Java Client Path Traversal
**类型:** 路径遍历 | **POC:** 是 | **投毒风险:** 1%
**仓库:** [kubernetes-client__java_CVE-2020-8570_client-java-parent-9_0_2_fixed](https://github.com/shoucheng3/kubernetes-client__java_CVE-2020-8570_client-java-parent-9_0_2_fixed)

### [CVE-2020-7961](CVE-2020-7961-neverhavenamee_CVE-2020-7961.md) 🔴

**名称:** CVE-2020-7961: Liferay Portal 反序列化导致远程代码执行
**类型:** 反序列化漏洞 | **POC:** 是 | **投毒风险:** 5%
**仓库:** [CVE-2020-7961](https://github.com/neverhavenamee/CVE-2020-7961)

### [CVE-2020-7961](CVE-2020-7961-pashayogi_CVE-2020-7961-Mass.md) 🔴 ⚠️

**名称:** CVE-2020-7961-Liferay Portal 反序列化RCE
**类型:** 反序列化RCE | **POC:** 是 | **投毒风险:** 99%
**仓库:** [CVE-2020-7961-Mass](https://github.com/pashayogi/CVE-2020-7961-Mass)

### [CVE-2020-7961](CVE-2020-7961-ShutdownRepo_CVE-2020-7961.md) 🔴

**名称:** CVE-2020-7961 - Liferay Portal 反序列化远程代码执行
**类型:** 反序列化漏洞 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [CVE-2020-7961](https://github.com/ShutdownRepo/CVE-2020-7961)

### [CVE-2020-7961](CVE-2020-7961-CrackerCat_CVE-2020-7961-Mass.md) 🔴

**名称:** CVE-2020-7961-Liferay Portal反序列化RCE
**类型:** 反序列化漏洞 | **POC:** 是 | **投毒风险:** 5%
**仓库:** [CVE-2020-7961-Mass](https://github.com/CrackerCat/CVE-2020-7961-Mass)

### [CVE-2020-7961](CVE-2020-7961-shacojx_POC-CVE-2020-7961-Token-iterate.md) 🔴

**名称:** CVE-2020-7961 Liferay Portal 反序列化RCE
**类型:** 反序列化RCE | **POC:** 是 | **投毒风险:** 10%
**仓库:** [POC-CVE-2020-7961-Token-iterate](https://github.com/shacojx/POC-CVE-2020-7961-Token-iterate)

### [CVE-2020-7961](CVE-2020-7961-shacojx_GLiferay-CVE-2020-7961-golang.md) 🔴

**名称:** CVE-2020-7961-Liferay-Deserialization
**类型:** 反序列化漏洞 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [GLiferay-CVE-2020-7961-golang](https://github.com/shacojx/GLiferay-CVE-2020-7961-golang)

### [CVE-2020-7961](CVE-2020-7961-shacojx_LifeRCEJsonWSTool-POC-CVE-2020-7961-Gui.md) 🔴

**名称:** CVE-2020-7961 Liferay Portal JSONWS反序列化RCE
**类型:** 反序列化漏洞 | **POC:** 是 | **投毒风险:** 5%
**仓库:** [LifeRCEJsonWSTool-POC-CVE-2020-7961-Gui](https://github.com/shacojx/LifeRCEJsonWSTool-POC-CVE-2020-7961-Gui)

### [CVE-2020-7961](CVE-2020-7961-mzer0one_CVE-2020-7961-POC.md) 🔴

**名称:** CVE-2020-7961-Liferay Portal-反序列化RCE
**类型:** 反序列化远程代码执行 | **POC:** 是 | **投毒风险:** 0%
**仓库:** [CVE-2020-7961-POC](https://github.com/mzer0one/CVE-2020-7961-POC)

### [CVE-2020-7961](CVE-2020-7961-thelostworldFree_CVE-2020-7961-payloads.md) 🔴

**名称:** CVE-2020-7961-Liferay Portal 反序列化RCE
**类型:** 反序列化远程代码执行 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [CVE-2020-7961-payloads](https://github.com/thelostworldFree/CVE-2020-7961-payloads)

### [CVE-2020-7842](CVE-2020-7842-GangTaegyeong_CVE-2020-7842.md)

**名称:** CVE-2020-7842-Netis Korea D'live AP-命令注入
**类型:** 命令注入 | **POC:** 部分可用 | **投毒风险:** 10%
**仓库:** [CVE-2020-7842](https://github.com/GangTaegyeong/CVE-2020-7842)

### [CVE-2020-7378](CVE-2020-7378-loganpkinfosec_CVE-2020-7378.md) 🔴

**名称:** CVE-2020-7378-OpenCRX-Unverified Password Change
**类型:** 未经验证的密码更改 | **POC:** 是 | **投毒风险:** 0%
**仓库:** [CVE-2020-7378](https://github.com/loganpkinfosec/CVE-2020-7378)

### [CVE-2020-7378](CVE-2020-7378-ruthvikvegunta_openCRX-CVE-2020-7378.md) 🔴

**名称:** CVE-2020-7378-OpenCRX-未验证密码更改
**类型:** 未验证密码更改 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [openCRX-CVE-2020-7378](https://github.com/ruthvikvegunta/openCRX-CVE-2020-7378)

### [CVE-2020-7247](CVE-2020-7247-minhluannguyen_CVE-2020-7247-reproducer.md) 🔴

**名称:** CVE-2020-7247-OpenSMTPD-RCE
**类型:** 远程代码执行 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [CVE-2020-7247-reproducer](https://github.com/minhluannguyen/CVE-2020-7247-reproducer)

### [CVE-2020-7247](CVE-2020-7247-presentdaypresenttime_shai_hulud.md) 🔴

**名称:** CVE-2020-7247 - OpenSMTPD 远程命令执行
**类型:** 远程命令执行 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [shai_hulud](https://github.com/presentdaypresenttime/shai_hulud)

### [CVE-2020-7247](CVE-2020-7247-SimonSchoeni_CVE-2020-7247-POC.md) 🔴

**名称:** CVE-2020-7247 - OpenSMTPD 远程代码执行
**类型:** 远程代码执行 | **POC:** 是 | **投毒风险:** 1%
**仓库:** [CVE-2020-7247-POC](https://github.com/SimonSchoeni/CVE-2020-7247-POC)

### [CVE-2020-7247](CVE-2020-7247-superzerosec_cve-2020-7247.md) 🔴

**名称:** CVE-2020-7247-OpenSMTPD-远程命令执行
**类型:** 远程命令执行 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [cve-2020-7247](https://github.com/superzerosec/cve-2020-7247)

### [CVE-2020-7247](CVE-2020-7247-f4T1H21_CVE-2020-7247.md) 🔴

**名称:** CVE-2020-7247 OpenSMTPD 远程命令执行
**类型:** 远程命令执行 | **POC:** 是 | **投毒风险:** 0%
**仓库:** [CVE-2020-7247](https://github.com/f4T1H21/CVE-2020-7247)

### [CVE-2020-7247](CVE-2020-7247-QTranspose_CVE-2020-7247-exploit.md) 🔴

**名称:** CVE-2020-7247-OpenSMTPD-远程代码执行
**类型:** 远程代码执行 | **POC:** 是 | **投毒风险:** 0%
**仓库:** [CVE-2020-7247-exploit](https://github.com/QTranspose/CVE-2020-7247-exploit)

### [CVE-2020-7247](CVE-2020-7247-bytescrappers_CVE-2020-7247.md) 🔴

**名称:** CVE-2020-7247-OpenSMTPD-远程代码执行
**类型:** 远程代码执行 | **POC:** 是 | **投毒风险:** 0%
**仓库:** [CVE-2020-7247](https://github.com/bytescrappers/CVE-2020-7247)

### [CVE-2020-7247](CVE-2020-7247-FiroSolutions_cve-2020-7247-exploit.md) 🔴

**名称:** CVE-2020-7247-OpenSMTPD-远程代码执行
**类型:** 远程代码执行 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [cve-2020-7247-exploit](https://github.com/FiroSolutions/cve-2020-7247-exploit)

### [CVE-2020-7247](CVE-2020-7247-r0lh_CVE-2020-7247.md) 🔴

**名称:** CVE-2020-7247-OpenSMTPD-远程代码执行
**类型:** 远程代码执行 | **POC:** 是 | **投毒风险:** 5%
**仓库:** [CVE-2020-7247](https://github.com/r0lh/CVE-2020-7247)

### [CVE-2020-5902](CVE-2020-5902-B1ack4sh_Blackash-CVE-2020-5902.md) 🔴

**名称:** CVE-2020-5902 F5 BIG-IP TMUI 远程代码执行
**类型:** 远程代码执行 (RCE) | **POC:** 是 | **投毒风险:** 5%
**仓库:** [Blackash-CVE-2020-5902](https://github.com/B1ack4sh/Blackash-CVE-2020-5902)

### [CVE-2020-5902](CVE-2020-5902-cristiano-corrado_f5_scanner.md) 🔴

**名称:** CVE-2020-5902-F5 BIG-IP-远程代码执行
**类型:** 远程代码执行 (RCE) | **POC:** 是 | **投毒风险:** 10%
**仓库:** [f5_scanner](https://github.com/cristiano-corrado/f5_scanner)

### [CVE-2020-5902](CVE-2020-5902-dunderhay_CVE-2020-5902.md) 🔴

**名称:** CVE-2020-5902-F5 Big-IP-TMUI远程代码执行
**类型:** 远程代码执行(RCE) | **POC:** 是 | **投毒风险:** 0%
**仓库:** [CVE-2020-5902](https://github.com/dunderhay/CVE-2020-5902)

### [CVE-2020-5902](CVE-2020-5902-yasserjanah_CVE-2020-5902.md) 🔴

**名称:** CVE-2020-5902-F5 BIG-IP TMUI 远程代码执行
**类型:** 远程代码执行 (RCE) | **POC:** 是 | **投毒风险:** 0%
**仓库:** [CVE-2020-5902](https://github.com/yasserjanah/CVE-2020-5902)

### [CVE-2020-5902](CVE-2020-5902-amitlttwo_CVE-2020-5902.md) 🔴

**名称:** CVE-2020-5902 - F5 BIG-IP TMUI 远程代码执行漏洞
**类型:** 远程代码执行 (RCE) | **POC:** 是 | **投毒风险:** 10%
**仓库:** [CVE-2020-5902](https://github.com/amitlttwo/CVE-2020-5902)

### [CVE-2020-5902](CVE-2020-5902-aqhmal_CVE-2020-5902-Scanner.md) 🔴

**名称:** CVE-2020-5902-F5 BIG-IP-TMUI远程代码执行
**类型:** 远程代码执行 (RCE) | **POC:** 是 | **投毒风险:** 0%
**仓库:** [CVE-2020-5902-Scanner](https://github.com/aqhmal/CVE-2020-5902-Scanner)

### [CVE-2020-5902](CVE-2020-5902-west9b_F5-BIG-IP-POC.md) 🔴

**名称:** CVE-2020-5902/CVE-2021-22986/CVE-2022-1388 - F5 BIG-IP TMUI 远程代码执行/命令执行/身份验证绕过
**类型:** 远程代码执行/命令执行/身份验证绕过 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [F5-BIG-IP-POC](https://github.com/west9b/F5-BIG-IP-POC)

### [CVE-2020-5902](CVE-2020-5902-z3n70_CVE-2020-5902.md) 🔴

**名称:** CVE-2020-5902-F5 BIG-IP TMUI 远程代码执行
**类型:** 远程代码执行 (RCE) | **POC:** 是 | **投毒风险:** 5%
**仓库:** [CVE-2020-5902](https://github.com/z3n70/CVE-2020-5902)

### [CVE-2020-5902](CVE-2020-5902-PushpenderIndia_CVE-2020-5902-Scanner.md) 🔴

**名称:** CVE-2020-5902 - F5 BIG-IP TMUI 远程代码执行
**类型:** 远程代码执行 (RCE) | **POC:** 是 | **投毒风险:** 10%
**仓库:** [CVE-2020-5902-Scanner](https://github.com/PushpenderIndia/CVE-2020-5902-Scanner)

### [CVE-2020-5902](CVE-2020-5902-jas502n_CVE-2020-5902.md) 🔴

**名称:** CVE-2020-5902-F5 BIG-IP TMUI-RCE
**类型:** 远程代码执行 (RCE) | **POC:** 是 | **投毒风险:** 0%
**仓库:** [CVE-2020-5902](https://github.com/jas502n/CVE-2020-5902)

### [CVE-2020-5902](CVE-2020-5902-haisenberg_CVE-2020-5902.md) 🔴

**名称:** CVE-2020-5902-F5 BIG-IP-TMUI 远程代码执行
**类型:** 远程代码执行 (RCE) | **POC:** 是 | **投毒风险:** 5%
**仓库:** [CVE-2020-5902](https://github.com/haisenberg/CVE-2020-5902)

### [CVE-2020-5902](CVE-2020-5902-faisalfs10x_F5-BIG-IP-CVE-2020-5902-shodan-scanner.md) 🔴

**名称:** CVE-2020-5902 F5 BIG-IP TMUI RCE
**类型:** 远程代码执行 (RCE) | **POC:** 是 | **投毒风险:** 10%
**仓库:** [F5-BIG-IP-CVE-2020-5902-shodan-scanner](https://github.com/faisalfs10x/F5-BIG-IP-CVE-2020-5902-shodan-scanner)

### [CVE-2020-5902](CVE-2020-5902-corelight_CVE-2020-5902-F5BigIP.md) 🔴

**名称:** CVE-2020-5902-F5 BIG-IP TMUI 远程代码执行
**类型:** 远程代码执行 (RCE) | **POC:** 是 | **投毒风险:** 0%
**仓库:** [CVE-2020-5902-F5BigIP](https://github.com/corelight/CVE-2020-5902-F5BigIP)

### [CVE-2020-5902](CVE-2020-5902-ludy-dev_BIG-IP-F5-TMUI-RCE-Vulnerability.md) 🔴

**名称:** CVE-2020-5902 F5 BIG-IP TMUI 远程代码执行
**类型:** 远程代码执行 (RCE) | **POC:** 是 | **投毒风险:** 0%
**仓库:** [BIG-IP-F5-TMUI-RCE-Vulnerability](https://github.com/ludy-dev/BIG-IP-F5-TMUI-RCE-Vulnerability)

### [CVE-2020-5902](CVE-2020-5902-murataydemir_CVE-2020-5902.md) 🔴

**名称:** CVE-2020-5902 F5 BIG-IP TMUI 远程代码执行
**类型:** 远程代码执行 (RCE) | **POC:** 是 | **投毒风险:** 0%
**仓库:** [CVE-2020-5902](https://github.com/murataydemir/CVE-2020-5902)

### [CVE-2020-5902](CVE-2020-5902-f5devcentral_cve-2020-5902-ioc-bigip-checker.md) 🔴

**名称:** CVE-2020-5902 - F5 BIG-IP TMUI 远程代码执行漏洞
**类型:** 远程代码执行 (RCE) | **POC:** 是 | **投毒风险:** 10%
**仓库:** [cve-2020-5902-ioc-bigip-checker](https://github.com/f5devcentral/cve-2020-5902-ioc-bigip-checker)

### [CVE-2020-5902](CVE-2020-5902-superzerosec_cve-2020-5902.md)

**名称:** CVE-2020-5902-F5 BIG-IP TMUI-RCE
**类型:** 远程代码执行 (RCE) | **POC:** 是 | **投毒风险:** 0%
**仓库:** [cve-2020-5902](https://github.com/superzerosec/cve-2020-5902)

### [CVE-2020-5902](CVE-2020-5902-halencarjunior_f5scan.md) 🔴

**名称:** CVE-2020-5902-F5 BIG-IP TMUI RCE
**类型:** 远程代码执行 (RCE) | **POC:** 是 | **投毒风险:** 0%
**仓库:** [f5scan](https://github.com/halencarjunior/f5scan)

### [CVE-2020-5902](CVE-2020-5902-TheCyberViking_CVE-2020-5902-Vuln-Checker.md) 🔴

**名称:** CVE-2020-5902 F5 BIG-IP TMUI 远程代码执行漏洞
**类型:** 远程代码执行 (RCE) | **POC:** 是 | **投毒风险:** 5%
**仓库:** [CVE-2020-5902-Vuln-Checker](https://github.com/TheCyberViking/CVE-2020-5902-Vuln-Checker)

### [CVE-2020-5902](CVE-2020-5902-rockmelodies_CVE-2020-5902-rce-gui.md) 🔴

**名称:** CVE-2020-5902-F5 BIG-IP TMUI 远程代码执行
**类型:** 远程代码执行 (RCE) | **POC:** 是 | **投毒风险:** 50%
**仓库:** [CVE-2020-5902-rce-gui](https://github.com/rockmelodies/CVE-2020-5902-rce-gui)

### [CVE-2020-5902](CVE-2020-5902-dnerzker_CVE-2020-5902.md) 🔴

**名称:** CVE-2020-5902-F5 BIG-IP TMUI RCE
**类型:** 远程代码执行 (RCE) | **POC:** 是 | **投毒风险:** 5%
**仓库:** [CVE-2020-5902](https://github.com/dnerzker/CVE-2020-5902)

### [CVE-2020-5902](CVE-2020-5902-momika233_cve-2020-5902.md)

**名称:** CVE-2020-5902 - F5 BIG-IP TMUI RCE
**类型:** 远程代码执行 (RCE) | **POC:** 是 | **投毒风险:** 5%
**仓库:** [cve-2020-5902](https://github.com/momika233/cve-2020-5902)

### [CVE-2020-5902](CVE-2020-5902-theLSA_f5-bigip-rce-cve-2020-5902.md)

**名称:** CVE-2020-5902 - F5 BIG-IP TMUI 远程代码执行
**类型:** 远程代码执行 (RCE) | **POC:** 是 | **投毒风险:** 1%
**仓库:** [f5-bigip-rce-cve-2020-5902](https://github.com/theLSA/f5-bigip-rce-cve-2020-5902)

### [CVE-2020-5902](CVE-2020-5902-Al1ex_CVE-2020-5902.md)

**名称:** CVE-2020-5902-F5 BIG-IP TMUI 远程代码执行
**类型:** 远程代码执行 (RCE) | **POC:** 是 | **投毒风险:** 10%
**仓库:** [CVE-2020-5902](https://github.com/Al1ex/CVE-2020-5902)

### [CVE-2020-5902](CVE-2020-5902-d4rk007_F5-Big-IP-CVE-2020-5902-mass-exploiter.md) 🔴

**名称:** CVE-2020-5902-F5 Big-IP TMUI 远程代码执行
**类型:** 远程代码执行 (RCE) | **POC:** 是 | **投毒风险:** 5%
**仓库:** [F5-Big-IP-CVE-2020-5902-mass-exploiter](https://github.com/d4rk007/F5-Big-IP-CVE-2020-5902-mass-exploiter)

### [CVE-2020-5902](CVE-2020-5902-GovindPalakkal_EvilRip.md) 🔴

**名称:** CVE-2020-5902-F5 BIG-IP TMUI RCE
**类型:** 远程代码执行 (RCE) | **POC:** 是 | **投毒风险:** 10%
**仓库:** [EvilRip](https://github.com/GovindPalakkal/EvilRip)

### [CVE-2020-5902](CVE-2020-5902-MrCl0wnLab_checker-CVE-2020-5902.md) 🔴

**名称:** CVE-2020-5902-F5 BIG-IP-TMUI-远程代码执行
**类型:** 远程代码执行 | **POC:** 是 | **投毒风险:** 0%
**仓库:** [checker-CVE-2020-5902](https://github.com/MrCl0wnLab/checker-CVE-2020-5902)

### [CVE-2020-5410](CVE-2020-5410-shoucheng3_spring-cloud__spring-cloud-config_CVE-2020-5410_2-1-8-RELEASE.md) 🔴

**名称:** CVE-2020-5410 Spring Cloud Config 目录遍历
**类型:** 目录遍历 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [spring-cloud__spring-cloud-config_CVE-2020-5410_2-1-8-RELEASE](https://github.com/shoucheng3/spring-cloud__spring-cloud-config_CVE-2020-5410_2-1-8-RELEASE)

### [CVE-2020-5410](CVE-2020-5410-osamahamad_CVE-2020-5410-POC.md) 🔴

**名称:** CVE-2020-5410 Spring Cloud Config 目录遍历漏洞
**类型:** 目录遍历 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [CVE-2020-5410-POC](https://github.com/osamahamad/CVE-2020-5410-POC)

### [CVE-2020-5410](CVE-2020-5410-dead5nd_config-demo.md) 🔴

**名称:** CVE-2020-5410 Spring Cloud Config 目录遍历
**类型:** 目录遍历 | **POC:** 是 | **投毒风险:** 5%
**仓库:** [config-demo](https://github.com/dead5nd/config-demo)

### [CVE-2020-5405](CVE-2020-5405-shoucheng3_spring-cloud__spring-cloud-config_CVE-2020-5405_2-1-6-RELEASE.md)

**名称:** CVE-2020-5405-Spring Cloud Config-目录遍历
**类型:** 目录遍历 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [spring-cloud__spring-cloud-config_CVE-2020-5405_2-1-6-RELEASE](https://github.com/shoucheng3/spring-cloud__spring-cloud-config_CVE-2020-5405_2-1-6-RELEASE)

### [CVE-2020-5377](CVE-2020-5377-h3x0v3rl0rd_CVE-2020-5377.md) 🔴

**名称:** CVE-2020-5377 - Dell OpenManage Server Administrator Path Traversal
**类型:** 路径遍历 | **POC:** 是 | **投毒风险:** 5%
**仓库:** [CVE-2020-5377](https://github.com/h3x0v3rl0rd/CVE-2020-5377)

### [CVE-2020-5248](CVE-2020-5248-venomnis_CVE-2020-5248.md) 🔴

**名称:** CVE-2020-5248 - GLPI 默认密钥解密漏洞
**类型:** 硬编码凭据 | **POC:** 是 | **投毒风险:** 0%
**仓库:** [CVE-2020-5248](https://github.com/venomnis/CVE-2020-5248)

### [CVE-2020-5248](CVE-2020-5248-Mkway_CVE-2020-5248.md) 🔴

**名称:** CVE-2020-5248 - GLPI 默认加密密钥漏洞
**类型:** 硬编码密钥 | **POC:** 是 | **投毒风险:** 1%
**仓库:** [CVE-2020-5248](https://github.com/Mkway/CVE-2020-5248)

### [CVE-2020-5142](CVE-2020-5142-hackerlawyer_CVE-2020-5142-POC-MB.md)

**名称:** CVE-2020-5142-SonicWall-SSLVPN-Stored-XSS
**类型:** 存储型跨站脚本 (Stored XSS) | **POC:** 是 | **投毒风险:** 5%
**仓库:** [CVE-2020-5142-POC-MB](https://github.com/hackerlawyer/CVE-2020-5142-POC-MB)

### [CVE-2020-36847](CVE-2020-36847-137f_PoC-CVE-2020-36847-WordPress-Plugin-4.2.2-RCE.md) 🔴

**名称:** CVE-2020-36847-Simple File List-RCE
**类型:** 远程代码执行 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [PoC-CVE-2020-36847-WordPress-Plugin-4.2.2-RCE](https://github.com/137f/PoC-CVE-2020-36847-WordPress-Plugin-4.2.2-RCE)

### [CVE-2020-36708](CVE-2020-36708-b1g-b33f_CVE-2020-36708.md) 🔴

**名称:** CVE-2020-36708 - WordPress Epsilon Framework Function Injection
**类型:** 函数注入 | **POC:** 是 | **投毒风险:** 0%
**仓库:** [CVE-2020-36708](https://github.com/b1g-b33f/CVE-2020-36708)

### [CVE-2020-36180](CVE-2020-36180-cuijiung_jackson-CVE-2020-36180.md) 🔴

**名称:** CVE-2020-36180 - Jackson-databind 反序列化漏洞
**类型:** 反序列化漏洞 | **POC:** 是 | **投毒风险:** 0%
**仓库:** [jackson-CVE-2020-36180](https://github.com/cuijiung/jackson-CVE-2020-36180)

### [CVE-2020-35848](CVE-2020-35848-sabbu143s_CVE_2020_35848.md) 🔴

**名称:** CVE-2020-35848 - Agentejo Cockpit NoSQL注入
**类型:** NoSQL注入 | **POC:** 是 | **投毒风险:** 1%
**仓库:** [CVE_2020_35848](https://github.com/sabbu143s/CVE_2020_35848)

### [CVE-2020-35667](CVE-2020-35667-Diekgbbtt_CVE-2020-35667-PoC.md)

**名称:** CVE-2020-35667-JetBrains TeamCity SSRF
**类型:** SSRF (服务器端请求伪造) | **POC:** 是 | **投毒风险:** 10%
**仓库:** [CVE-2020-35667-PoC](https://github.com/Diekgbbtt/CVE-2020-35667-PoC)

### [CVE-2020-35667](CVE-2020-35667-stefan-500_teamcity-idea-cve-2020-35667-poc.md) 🔴

**名称:** CVE-2020-35667 - TeamCity IntelliJ IDEA Plugin SSRF 漏洞
**类型:** SSRF | **POC:** 是 | **投毒风险:** 10%
**仓库:** [teamcity-idea-cve-2020-35667-poc](https://github.com/stefan-500/teamcity-idea-cve-2020-35667-poc)

### [CVE-2020-35590](CVE-2020-35590-N4nj0_CVE-2020-35590.md)

**名称:** CVE-2020-35590-Limit Login Attempts Reloaded-登录限制绕过
**类型:** 速率限制绕过 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [CVE-2020-35590](https://github.com/N4nj0/CVE-2020-35590)

### [CVE-2020-35460](CVE-2020-35460-shoucheng3_joniles__mpxj_CVE-2020-35460_8-3-4.md)

**名称:** CVE-2020-35460 - MPXJ Directory Traversal
**类型:** 目录遍历 | **POC:** 否（但漏洞信息明确，可构造利用） | **投毒风险:** 5%
**仓库:** [joniles__mpxj_CVE-2020-35460_8-3-4](https://github.com/shoucheng3/joniles__mpxj_CVE-2020-35460_8-3-4)

### [CVE-2020-3452](CVE-2020-3452-abrewer251_CVE-2020-3452_Cisco_ASA_PathTraversal.md) 🔴

**名称:** CVE-2020-3452 Cisco ASA/FTD 路径遍历漏洞
**类型:** 路径遍历 | **POC:** 是 | **投毒风险:** 0%
**仓库:** [CVE-2020-3452_Cisco_ASA_PathTraversal](https://github.com/abrewer251/CVE-2020-3452_Cisco_ASA_PathTraversal)

### [CVE-2020-3452](CVE-2020-3452-Cappricio-Securities_CVE-2020-3452.md) 🔴

**名称:** CVE-2020-3452-Cisco ASA/FTD 路径遍历漏洞
**类型:** 路径遍历 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [CVE-2020-3452](https://github.com/Cappricio-Securities/CVE-2020-3452)

### [CVE-2020-3452](CVE-2020-3452-cygenta_CVE-2020-3452.md) 🔴

**名称:** CVE-2020-3452 Cisco ASA/FTD 路径遍历漏洞
**类型:** 路径遍历 | **POC:** 是 | **投毒风险:** 5%
**仓库:** [CVE-2020-3452](https://github.com/cygenta/CVE-2020-3452)

### [CVE-2020-3452](CVE-2020-3452-iveresk_cve-2020-3452.md) 🔴

**名称:** CVE-2020-3452 Cisco ASA/FTD 目录遍历漏洞
**类型:** 目录遍历 | **POC:** 是 | **投毒风险:** 5%
**仓库:** [cve-2020-3452](https://github.com/iveresk/cve-2020-3452)

### [CVE-2020-3452](CVE-2020-3452-Veids_CVE-2020-3452_auto.md) 🔴

**名称:** CVE-2020-3452 Cisco ASA/FTD 路径遍历漏洞
**类型:** 路径遍历 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [CVE-2020-3452_auto](https://github.com/Veids/CVE-2020-3452_auto)

### [CVE-2020-3452](CVE-2020-3452-darklotuskdb_CISCO-CVE-2020-3452-Scanner-Exploiter.md) 🔴

**名称:** CVE-2020-3452-Cisco ASA/FTD Read-Only Path Traversal
**类型:** 目录遍历 | **POC:** 是 | **投毒风险:** 1%
**仓库:** [CISCO-CVE-2020-3452-Scanner-Exploiter](https://github.com/darklotuskdb/CISCO-CVE-2020-3452-Scanner-Exploiter)

### [CVE-2020-3452](CVE-2020-3452-sujaygr8_CVE-2020-3452.md) 🔴

**名称:** CVE-2020-3452-Cisco ASA/FTD 目录遍历漏洞
**类型:** 目录遍历 | **POC:** 是 | **投毒风险:** 0%
**仓库:** [CVE-2020-3452](https://github.com/sujaygr8/CVE-2020-3452)

### [CVE-2020-3452](CVE-2020-3452-paran0id34_CVE-2020-3452.md) 🔴

**名称:** CVE-2020-3452 - Cisco ASA/FTD 目录遍历
**类型:** 目录遍历 | **POC:** 是 | **投毒风险:** 0%
**仓库:** [CVE-2020-3452](https://github.com/paran0id34/CVE-2020-3452)

### [CVE-2020-3452](CVE-2020-3452-faisalfs10x_Cisco-CVE-2020-3452-shodan-scanner.md) 🔴

**名称:** CVE-2020-3452-Cisco ASA/FTD 路径遍历漏洞
**类型:** 路径遍历 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [Cisco-CVE-2020-3452-shodan-scanner](https://github.com/faisalfs10x/Cisco-CVE-2020-3452-shodan-scanner)

### [CVE-2020-3452](CVE-2020-3452-fuzzlove_Cisco-ASA-FTD-Web-Services-Traversal.md) 🔴

**名称:** CVE-2020-3452 Cisco ASA/FTD Web Services Read-Only Path Traversal
**类型:** 目录遍历 | **POC:** 是 | **投毒风险:** 0%
**仓库:** [Cisco-ASA-FTD-Web-Services-Traversal](https://github.com/fuzzlove/Cisco-ASA-FTD-Web-Services-Traversal)

### [CVE-2020-3452](CVE-2020-3452-grim3_CVE-2020-3452.md) 🔴

**名称:** CVE-2020-3452 Cisco ASA/FTD 路径遍历漏洞
**类型:** 路径遍历 | **POC:** 是 | **投毒风险:** 0%
**仓库:** [CVE-2020-3452](https://github.com/grim3/CVE-2020-3452)

### [CVE-2020-3452](CVE-2020-3452-ludy-dev_Cisco-ASA-LFI.md) 🔴

**名称:** CVE-2020-3452 Cisco ASA/FTD 路径遍历漏洞
**类型:** 路径遍历 | **POC:** 是 | **投毒风险:** 0%
**仓库:** [Cisco-ASA-LFI](https://github.com/ludy-dev/Cisco-ASA-LFI)

### [CVE-2020-3452](CVE-2020-3452-Gh0st0ne_http-vuln-cve2020-3452.nse.md) 🔴

**名称:** CVE-2020-3452 Cisco ASA/FTD Read-Only Path Traversal
**类型:** 路径遍历 | **POC:** 是 | **投毒风险:** 0%
**仓库:** [http-vuln-cve2020-3452.nse](https://github.com/Gh0st0ne/http-vuln-cve2020-3452.nse)

### [CVE-2020-3452](CVE-2020-3452-3ndG4me_CVE-2020-3452-Exploit.md) 🔴

**名称:** CVE-2020-3452 Cisco ASA/FTD 路径遍历漏洞
**类型:** 路径遍历 | **POC:** 是 | **投毒风险:** 0%
**仓库:** [CVE-2020-3452-Exploit](https://github.com/3ndG4me/CVE-2020-3452-Exploit)

### [CVE-2020-3452](CVE-2020-3452-murataydemir_CVE-2020-3452.md) 🔴

**名称:** CVE-2020-3452 Cisco ASA/FTD Read-Only Path Traversal
**类型:** 路径遍历 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [CVE-2020-3452](https://github.com/murataydemir/CVE-2020-3452)

### [CVE-2020-3452](CVE-2020-3452-PR3R00T_CVE-2020-3452-Cisco-Scanner.md) 🔴

**名称:** CVE-2020-3452 Cisco ASA/FTD 目录遍历漏洞
**类型:** 目录遍历 | **POC:** 是 | **投毒风险:** 0%
**仓库:** [CVE-2020-3452-Cisco-Scanner](https://github.com/PR3R00T/CVE-2020-3452-Cisco-Scanner)

### [CVE-2020-3452](CVE-2020-3452-foulenzer_CVE-2020-3452.md) 🔴

**名称:** CVE-2020-3452 Cisco ASA/FTD 路径遍历漏洞
**类型:** 路径遍历 | **POC:** 是 | **投毒风险:** 0%
**仓库:** [CVE-2020-3452](https://github.com/foulenzer/CVE-2020-3452)

### [CVE-2020-3452](CVE-2020-3452-0x5ECF4ULT_CVE-2020-3452.md) 🔴

**名称:** CVE-2020-3452 Cisco ASA/FTD 路径遍历漏洞
**类型:** 路径遍历 | **POC:** 是 | **投毒风险:** 5%
**仓库:** [CVE-2020-3452](https://github.com/0x5ECF4ULT/CVE-2020-3452)

### [CVE-2020-3452](CVE-2020-3452-mr-r3b00t_CVE-2020-3452.md) 🔴

**名称:** CVE-2020-3452 Cisco ASA/FTD 目录遍历漏洞
**类型:** 目录遍历 | **POC:** 是 | **投毒风险:** 0%
**仓库:** [CVE-2020-3452](https://github.com/mr-r3b00t/CVE-2020-3452)

### [CVE-2020-3452](CVE-2020-3452-Loneyers_cve-2020-3452.md) 🔴

**名称:** CVE-2020-3452 - Cisco ASA/FTD Read-Only Path Traversal
**类型:** 目录遍历 | **POC:** 是 | **投毒风险:** 0%
**仓库:** [cve-2020-3452](https://github.com/Loneyers/cve-2020-3452)

### [CVE-2020-3452](CVE-2020-3452-XDev05_CVE-2020-3452-PoC.md) 🔴

**名称:** CVE-2020-3452 Cisco ASA/FTD 目录遍历漏洞
**类型:** 目录遍历 | **POC:** 是 | **投毒风险:** 5%
**仓库:** [CVE-2020-3452-PoC](https://github.com/XDev05/CVE-2020-3452-PoC)

### [CVE-2020-3452](CVE-2020-3452-Aviksaikat_CVE-2020-3452.md) 🔴

**名称:** CVE-2020-3452 Cisco ASA/FTD 目录遍历漏洞
**类型:** 目录遍历 | **POC:** 是 | **投毒风险:** 0%
**仓库:** [CVE-2020-3452](https://github.com/Aviksaikat/CVE-2020-3452)

### [CVE-2020-29607](CVE-2020-29607-CaelumIsMe_CVE-2020-29607-POC.md) 🔴

**名称:** CVE-2020-29607-Pluck CMS-文件上传绕过导致RCE
**类型:** 文件上传绕过 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [CVE-2020-29607-POC](https://github.com/CaelumIsMe/CVE-2020-29607-POC)

### [CVE-2020-29607](CVE-2020-29607-Alienfader_CVE-2020-29607.md) 🔴

**名称:** CVE-2020-29607-Pluck CMS-文件上传绕过导致远程代码执行
**类型:** 文件上传绕过 | **POC:** 是 | **投毒风险:** 5%
**仓库:** [CVE-2020-29607](https://github.com/Alienfader/CVE-2020-29607)

### [CVE-2020-29607](CVE-2020-29607-0xN7y_CVE-2020-29607.md) 🔴

**名称:** CVE-2020-29607-Pluck CMS-文件上传绕过导致远程代码执行
**类型:** 文件上传绕过 | **POC:** 是 | **投毒风险:** 0%
**仓库:** [CVE-2020-29607](https://github.com/0xN7y/CVE-2020-29607)

### [CVE-2020-29607](CVE-2020-29607-ar2o3_CVE-2020-29607.md) 🔴

**名称:** CVE-2020-29607-Pluck CMS-文件上传绕过
**类型:** 文件上传绕过 | **POC:** 是 | **投毒风险:** 0%
**仓库:** [CVE-2020-29607](https://github.com/ar2o3/CVE-2020-29607)

### [CVE-2020-29204](CVE-2020-29204-shoucheng3_xuxueli__xxl-job_CVE-2020-29204_2-2-0.md)

**名称:** CVE-2020-29204-XXL-JOB-存储型XSS
**类型:** 存储型XSS | **POC:** 是 | **投毒风险:** 0%
**仓库:** [xuxueli__xxl-job_CVE-2020-29204_2-2-0](https://github.com/shoucheng3/xuxueli__xxl-job_CVE-2020-29204_2-2-0)

### [CVE-2020-28458](CVE-2020-28458-fazilbaig1_CVE-2020-28458.md)

**名称:** CVE-2020-28458-datatables.net-Prototype Pollution
**类型:** Prototype Pollution | **POC:** 是 | **投毒风险:** 10%
**仓库:** [CVE-2020-28458](https://github.com/fazilbaig1/CVE-2020-28458)

### [CVE-2020-27955](CVE-2020-27955-the-chivalrousZ_cve-2020-27955.md) 🔴

**名称:** CVE-2020-27955 Git LFS Remote Code Execution
**类型:** 远程代码执行 (RCE) | **POC:** 是 | **投毒风险:** 1%
**仓库:** [cve-2020-27955](https://github.com/the-chivalrousZ/cve-2020-27955)

### [CVE-2020-27955](CVE-2020-27955-Kimorea_CVE-2020-27955-LFS.md) 🔴

**名称:** CVE-2020-27955-Git LFS-RCE
**类型:** 远程代码执行 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [CVE-2020-27955-LFS](https://github.com/Kimorea/CVE-2020-27955-LFS)

### [CVE-2020-27955](CVE-2020-27955-z50913_CVE-2020-27955.md) 🔴

**名称:** CVE-2020-27955 Git LFS Remote Code Execution
**类型:** Remote Code Execution | **POC:** 是 | **投毒风险:** 10%
**仓库:** [CVE-2020-27955](https://github.com/z50913/CVE-2020-27955)

### [CVE-2020-27955](CVE-2020-27955-userxfan_cve-2020-27955.md) 🔴

**名称:** CVE-2020-27955-Git LFS Remote Code Execution
**类型:** 远程代码执行 | **POC:** 是 | **投毒风险:** 0%
**仓库:** [cve-2020-27955](https://github.com/userxfan/cve-2020-27955)

### [CVE-2020-27955](CVE-2020-27955-whitetea2424_CVE-2020-27955-LFS-main.md) 🔴

**名称:** CVE-2020-27955 Git LFS RCE
**类型:** 远程代码执行 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [CVE-2020-27955-LFS-main](https://github.com/whitetea2424/CVE-2020-27955-LFS-main)

### [CVE-2020-27955](CVE-2020-27955-FrostsaberX_CVE-2020-27955.md) 🔴

**名称:** CVE-2020-27955 Git LFS Remote Code Execution
**类型:** Remote Code Execution | **POC:** 是 | **投毒风险:** 10%
**仓库:** [CVE-2020-27955](https://github.com/FrostsaberX/CVE-2020-27955)

### [CVE-2020-27955](CVE-2020-27955-Marsable_CVE-2020-27955-LFS.md) 🔴

**名称:** CVE-2020-27955-Git LFS-RCE
**类型:** 远程代码执行 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [CVE-2020-27955-LFS](https://github.com/Marsable/CVE-2020-27955-LFS)

### [CVE-2020-27955](CVE-2020-27955-nob0dy-3389_CVE-2020-27955.md) 🔴

**名称:** CVE-2020-27955-Git LFS-RCE
**类型:** 远程代码执行 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [CVE-2020-27955](https://github.com/nob0dy-3389/CVE-2020-27955)

### [CVE-2020-27955](CVE-2020-27955-Arnoldqqq_CVE-2020-27955.md) 🔴

**名称:** CVE-2020-27955-Git LFS-RCE
**类型:** 远程代码执行 | **POC:** 是 | **投毒风险:** 0%
**仓库:** [CVE-2020-27955](https://github.com/Arnoldqqq/CVE-2020-27955)

### [CVE-2020-27955](CVE-2020-27955-IanSmith123_CVE-2020-27955.md) 🔴 ⚠️

**名称:** CVE-2020-27955 Git LFS RCE
**类型:** 远程代码执行 | **POC:** 是 | **投毒风险:** 80%
**仓库:** [CVE-2020-27955](https://github.com/IanSmith123/CVE-2020-27955)

### [CVE-2020-27955](CVE-2020-27955-HK69s_CVE-2020-27955.md) 🔴

**名称:** CVE-2020-27955-Git LFS-RCE
**类型:** 远程代码执行 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [CVE-2020-27955](https://github.com/HK69s/CVE-2020-27955)

### [CVE-2020-27955](CVE-2020-27955-DeeLMind_CVE-2020-27955-LFS.md) 🔴

**名称:** CVE-2020-27955-Git LFS-RCE
**类型:** 远程代码执行 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [CVE-2020-27955-LFS](https://github.com/DeeLMind/CVE-2020-27955-LFS)

### [CVE-2020-27955](CVE-2020-27955-NeoDarwin_CVE-2020-27955.md) 🔴

**名称:** CVE-2020-27955 - Git LFS Remote Code Execution
**类型:** 远程代码执行 (RCE) | **POC:** 是 | **投毒风险:** 0%
**仓库:** [CVE-2020-27955](https://github.com/NeoDarwin/CVE-2020-27955)

### [CVE-2020-27955](CVE-2020-27955-ExploitBox_git-lfs-RCE-exploit-CVE-2020-27955.md) 🔴

**名称:** CVE-2020-27955-Git LFS-RCE
**类型:** 远程代码执行 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [git-lfs-RCE-exploit-CVE-2020-27955](https://github.com/ExploitBox/git-lfs-RCE-exploit-CVE-2020-27955)

### [CVE-2020-27955](CVE-2020-27955-TheTh1nk3r_cve-2020-27955.md) 🔴

**名称:** CVE-2020-27955 - Git LFS Remote Code Execution
**类型:** Remote Code Execution (RCE) | **POC:** 是 | **投毒风险:** 0%
**仓库:** [cve-2020-27955](https://github.com/TheTh1nk3r/cve-2020-27955)

### [CVE-2020-27955](CVE-2020-27955-r00t4dm_CVE-2020-27955.md) 🔴

**名称:** CVE-2020-27955 Git LFS RCE
**类型:** 远程代码执行 (RCE) | **POC:** 是 | **投毒风险:** 0%
**仓库:** [CVE-2020-27955](https://github.com/r00t4dm/CVE-2020-27955)

### [CVE-2020-27955](CVE-2020-27955-yhsung_cve-2020-27955-poc.md) 🔴

**名称:** CVE-2020-27955-Git LFS-RCE
**类型:** RCE | **POC:** 是 | **投毒风险:** 10%
**仓库:** [cve-2020-27955-poc](https://github.com/yhsung/cve-2020-27955-poc)

### [CVE-2020-27955](CVE-2020-27955-ExploitBox_git-lfs-RCE-exploit-CVE-2020-27955-Go.md) 🔴

**名称:** CVE-2020-27955 Git LFS Remote Code Execution
**类型:** 远程代码执行 | **POC:** 是 | **投毒风险:** 0%
**仓库:** [git-lfs-RCE-exploit-CVE-2020-27955-Go](https://github.com/ExploitBox/git-lfs-RCE-exploit-CVE-2020-27955-Go)

### [CVE-2020-27603](CVE-2020-27603-hannob_CVE-2020-27603-bbb-libreoffice-poc.md) 🔴 ⚠️

**名称:** CVE-2020-27603-BigBlueButton-文件包含
**类型:** 文件包含 | **POC:** 是 | **投毒风险:** 99%
**仓库:** [CVE-2020-27603-bbb-libreoffice-poc](https://github.com/hannob/CVE-2020-27603-bbb-libreoffice-poc)

### [CVE-2020-27219](CVE-2020-27219-shoucheng3_eclipse__hawkbit_CVE-2020-27219_0-3-0M6.md)

**名称:** CVE-2020-27219-Eclipse Hawkbit-XSS
**类型:** 跨站脚本 (XSS) | **POC:** 是 | **投毒风险:** 0%
**仓库:** [eclipse__hawkbit_CVE-2020-27219_0-3-0M6](https://github.com/shoucheng3/eclipse__hawkbit_CVE-2020-27219_0-3-0M6)

### [CVE-2020-27219](CVE-2020-27219-shoucheng3_eclipse__hawkbit_CVE-2020-27219_0-3-0M6.md)

**名称:** CVE-2020-27219-Eclipse Hawkbit-XSS
**类型:** XSS | **POC:** 是 | **投毒风险:** 0%
**仓库:** [eclipse__hawkbit_CVE-2020-27219_0-3-0M6](https://github.com/shoucheng3/eclipse__hawkbit_CVE-2020-27219_0-3-0M6)

### [CVE-2020-26259](CVE-2020-26259-cuijiung_xstream-CVE-2020-26259.md)

**名称:** CVE-2020-26259-XStream-任意文件删除
**类型:** 任意文件删除 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [xstream-CVE-2020-26259](https://github.com/cuijiung/xstream-CVE-2020-26259)

### [CVE-2020-26259](CVE-2020-26259-Al1ex_CVE-2020-26259.md)

**名称:** CVE-2020-26259-XStream-任意文件删除
**类型:** 任意文件删除 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [CVE-2020-26259](https://github.com/Al1ex/CVE-2020-26259)

### [CVE-2020-26259](CVE-2020-26259-jas502n_CVE-2020-26259.md)

**名称:** CVE-2020-26259-XStream-任意文件删除
**类型:** 任意文件删除 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [CVE-2020-26259](https://github.com/jas502n/CVE-2020-26259)

### [CVE-2020-26258](CVE-2020-26258-cuijiung_xstream-CVE-2020-26258.md)

**名称:** CVE-2020-26258 XStream Server-Side Request Forgery
**类型:** Server-Side Request Forgery (SSRF) | **POC:** 是 | **投毒风险:** 10%
**仓库:** [xstream-CVE-2020-26258](https://github.com/cuijiung/xstream-CVE-2020-26258)

### [CVE-2020-26258](CVE-2020-26258-Al1ex_CVE-2020-26258.md)

**名称:** CVE-2020-26258-XStream-SSRF
**类型:** SSRF (Server-Side Request Forgery) | **POC:** 是 | **投毒风险:** 0%
**仓库:** [CVE-2020-26258](https://github.com/Al1ex/CVE-2020-26258)

### [CVE-2020-26217](CVE-2020-26217-cuijiung_xstream-CVE-2020-26217.md) 🔴

**名称:** CVE-2020-26217-XStream-远程代码执行
**类型:** 远程代码执行 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [xstream-CVE-2020-26217](https://github.com/cuijiung/xstream-CVE-2020-26217)

### [CVE-2020-26217](CVE-2020-26217-epicosy_XStream-1.md) 🔴

**名称:** CVE-2020-26217-XStream-远程代码执行
**类型:** 远程代码执行 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [XStream-1](https://github.com/epicosy/XStream-1)

### [CVE-2020-26217](CVE-2020-26217-Al1ex_CVE-2020-26217.md) 🔴

**名称:** CVE-2020-26217-XStream-RCE
**类型:** 远程代码执行 (RCE) | **POC:** 是 | **投毒风险:** 5%
**仓库:** [CVE-2020-26217](https://github.com/Al1ex/CVE-2020-26217)

### [CVE-2020-26217](CVE-2020-26217-novysodope_CVE-2020-26217-XStream-RCE-POC.md) 🔴

**名称:** CVE-2020-26217-XStream-RCE
**类型:** 远程代码执行 | **POC:** 是 | **投毒风险:** 1%
**仓库:** [CVE-2020-26217-XStream-RCE-POC](https://github.com/novysodope/CVE-2020-26217-XStream-RCE-POC)

### [CVE-2020-26217](CVE-2020-26217-shoucheng3_x-stream__xstream_CVE-2020-26217_1-4-14-java7.md) 🔴

**名称:** CVE-2020-26217-XStream-远程代码执行
**类型:** 远程代码执行 | **POC:** 是 | **投毒风险:** 1%
**仓库:** [x-stream__xstream_CVE-2020-26217_1-4-14-java7](https://github.com/shoucheng3/x-stream__xstream_CVE-2020-26217_1-4-14-java7)

### [CVE-2020-26217](CVE-2020-26217-Kairo-one_CVE-2020-26217-XStream.md) 🔴

**名称:** CVE-2020-26217 XStream 远程代码执行
**类型:** 远程代码执行 | **POC:** 是 | **投毒风险:** 0%
**仓库:** [CVE-2020-26217-XStream](https://github.com/Kairo-one/CVE-2020-26217-XStream)

### [CVE-2020-2551](CVE-2020-2551-B1ack4sh_Blackash-CVE-2020-2551.md) 🔴

**名称:** CVE-2020-2551-WebLogic IIOP RCE
**类型:** 远程代码执行 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [Blackash-CVE-2020-2551](https://github.com/B1ack4sh/Blackash-CVE-2020-2551)

### [CVE-2020-2551](CVE-2020-2551-hktalent_CVE-2020-2551.md) 🔴

**名称:** CVE-2020-2551-Oracle WebLogic Server-IIOP反序列化
**类型:** 反序列化漏洞 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [CVE-2020-2551](https://github.com/hktalent/CVE-2020-2551)

### [CVE-2020-2551](CVE-2020-2551-zzwlpx_weblogicPoc.md) 🔴

**名称:** CVE-2020-2551 - Oracle WebLogic Server IIOP反序列化漏洞
**类型:** 反序列化漏洞 | **POC:** 是 | **投毒风险:** 20%
**仓库:** [weblogicPoc](https://github.com/zzwlpx/weblogicPoc)

### [CVE-2020-2551](CVE-2020-2551-ar2o3_CVE-Exploit.md) 🔴

**名称:** CVE-2020-2551 - Oracle WebLogic Server IIOP 反序列化漏洞
**类型:** 反序列化漏洞 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [CVE-Exploit](https://github.com/ar2o3/CVE-Exploit)

### [CVE-2020-2551](CVE-2020-2551-Dido1960_Weblogic-CVE-2020-2551-To-Internet.md) 🔴

**名称:** CVE-2020-2551 - Oracle WebLogic Server IIOP 反序列化漏洞
**类型:** 反序列化漏洞 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [Weblogic-CVE-2020-2551-To-Internet](https://github.com/Dido1960/Weblogic-CVE-2020-2551-To-Internet)

### [CVE-2020-2551](CVE-2020-2551-Y4er_CVE-2020-2551.md) 🔴

**名称:** CVE-2020-2551 - Oracle WebLogic Server IIOP反序列化漏洞
**类型:** 反序列化漏洞 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [CVE-2020-2551](https://github.com/Y4er/CVE-2020-2551)

### [CVE-2020-2551](CVE-2020-2551-DaMinGshidashi_CVE-2020-2551.md) 🔴

**名称:** CVE-2020-2551-WebLogic-IIOP反序列化RCE
**类型:** 反序列化远程代码执行 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [CVE-2020-2551](https://github.com/DaMinGshidashi/CVE-2020-2551)

### [CVE-2020-2551](CVE-2020-2551-jas502n_CVE-2020-2551.md) 🔴

**名称:** CVE-2020-2551 WebLogic RCE via IIOP
**类型:** 远程代码执行 (RCE) | **POC:** 是 | **投毒风险:** 10%
**仓库:** [CVE-2020-2551](https://github.com/jas502n/CVE-2020-2551)

### [CVE-2020-24913](CVE-2020-24913-agarma_CVE-2020-24913-PoC.md) 🔴

**名称:** CVE-2020-24913-QCubed-SQL注入
**类型:** SQL注入 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [CVE-2020-24913-PoC](https://github.com/agarma/CVE-2020-24913-PoC)

### [CVE-2020-24913](CVE-2020-24913-shpaw415_CVE-2020-24913-exploit.md) 🔴

**名称:** CVE-2020-24913-QCubed-SQL注入
**类型:** SQL注入 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [CVE-2020-24913-exploit](https://github.com/shpaw415/CVE-2020-24913-exploit)

### [CVE-2020-24186](CVE-2020-24186-sec-dojo-com_CVE-2020-24186.md) 🔴

**名称:** CVE-2020-24186 - WP-Discuz 7.0.4 远程代码执行
**类型:** 任意文件上传导致远程代码执行 | **POC:** 是 | **投毒风险:** 0%
**仓库:** [CVE-2020-24186](https://github.com/sec-dojo-com/CVE-2020-24186)

### [CVE-2020-24186](CVE-2020-24186-GazettEl_CVE-2020-24186.md) 🔴

**名称:** CVE-2020-24186-wpDiscuz-RCE
**类型:** 远程代码执行 | **POC:** 是 | **投毒风险:** 1%
**仓库:** [CVE-2020-24186](https://github.com/GazettEl/CVE-2020-24186)

### [CVE-2020-24186](CVE-2020-24186-substing_CVE-2020-24186_reverse_shell_upload.md) 🔴

**名称:** CVE-2020-24186-wpDiscuz-RCE
**类型:** 远程代码执行(RCE) | **POC:** 是 | **投毒风险:** 10%
**仓库:** [CVE-2020-24186_reverse_shell_upload](https://github.com/substing/CVE-2020-24186_reverse_shell_upload)

### [CVE-2020-24186](CVE-2020-24186-meicookies_CVE-2020-24186.md) 🔴

**名称:** CVE-2020-24186-wpDiscuz-任意文件上传
**类型:** 任意文件上传 | **POC:** 是 | **投毒风险:** 0%
**仓库:** [CVE-2020-24186](https://github.com/meicookies/CVE-2020-24186)

### [CVE-2020-24186](CVE-2020-24186-hev0x_CVE-2020-24186-wpDiscuz-7.0.4-RCE.md) 🔴

**名称:** CVE-2020-24186-wpDiscuz-7.0.4-RCE
**类型:** 远程代码执行 | **POC:** 是 | **投毒风险:** 0%
**仓库:** [CVE-2020-24186-wpDiscuz-7.0.4-RCE](https://github.com/hev0x/CVE-2020-24186-wpDiscuz-7.0.4-RCE)

### [CVE-2020-24186](CVE-2020-24186-Sakura-501_CVE-2020-24186-exploit.md) 🔴

**名称:** CVE-2020-24186-wpDiscuz-RCE
**类型:** 远程代码执行 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [CVE-2020-24186-exploit](https://github.com/Sakura-501/CVE-2020-24186-exploit)

### [CVE-2020-2261](CVE-2020-2261-shoucheng3_jenkinsci__perfecto-plugin_CVE-2020-2261_1-17.md) 🔴

**名称:** CVE-2020-2261-Jenkins Perfecto Plugin-命令注入
**类型:** 命令注入 | **POC:** 是 | **投毒风险:** 0%
**仓库:** [jenkinsci__perfecto-plugin_CVE-2020-2261_1-17](https://github.com/shoucheng3/jenkinsci__perfecto-plugin_CVE-2020-2261_1-17)

### [CVE-2020-2261](CVE-2020-2261-shoucheng3_jenkinsci__perfecto-plugin_CVE-2020-2261_1-17.md) 🔴

**名称:** CVE-2020-2261 Jenkins Perfecto Plugin 命令注入
**类型:** 命令注入 | **POC:** 是 | **投毒风险:** 0%
**仓库:** [jenkinsci__perfecto-plugin_CVE-2020-2261_1-17](https://github.com/shoucheng3/jenkinsci__perfecto-plugin_CVE-2020-2261_1-17)

### [CVE-2020-21365](CVE-2020-21365-andrei2308_CVE-2020-21365.md) 🔴

**名称:** CVE-2020-21365-wkhtmltopdf-目录遍历
**类型:** 目录遍历 | **POC:** 是 | **投毒风险:** 0%
**仓库:** [CVE-2020-21365](https://github.com/andrei2308/CVE-2020-21365)

### [CVE-2020-21365](CVE-2020-21365-samaellovecraft_CVE-2020-21365.md) 🔴

**名称:** CVE-2020-21365-wkhtmltopdf-目录遍历
**类型:** 目录遍历 | **POC:** 是 | **投毒风险:** 0%
**仓库:** [CVE-2020-21365](https://github.com/samaellovecraft/CVE-2020-21365)

### [CVE-2020-21365](CVE-2020-21365-andrei2308_CVE-2020-21365-PoC.md) 🔴

**名称:** CVE-2020-21365-wkhtmltopdf-目录遍历
**类型:** 目录遍历 | **POC:** 是 | **投毒风险:** 0%
**仓库:** [CVE-2020-21365-PoC](https://github.com/andrei2308/CVE-2020-21365-PoC)

### [CVE-2020-17530](CVE-2020-17530-daehyeok0618_CVE-2020-17530.md) 🔴

**名称:** CVE-2020-17530-Apache Struts-远程代码执行
**类型:** 远程代码执行 | **POC:** 是 | **投毒风险:** 0%
**仓库:** [CVE-2020-17530](https://github.com/daehyeok0618/CVE-2020-17530)

### [CVE-2020-17530](CVE-2020-17530-keyuan15_CVE-2020-17530.md) 🔴

**名称:** CVE-2020-17530-Apache Struts2-远程代码执行
**类型:** 远程代码执行 | **POC:** 是 | **投毒风险:** 5%
**仓库:** [CVE-2020-17530](https://github.com/keyuan15/CVE-2020-17530)

### [CVE-2020-17530](CVE-2020-17530-killmonday_CVE-2020-17530-s2-061.md) 🔴

**名称:** CVE-2020-17530-Apache Struts2-OGNL表达式注入
**类型:** OGNL表达式注入 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [CVE-2020-17530-s2-061](https://github.com/killmonday/CVE-2020-17530-s2-061)

### [CVE-2020-17530](CVE-2020-17530-uzzzval_CVE-2020-17530.md) 🔴

**名称:** CVE-2020-17530-Apache Struts-远程代码执行
**类型:** 远程代码执行 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [CVE-2020-17530](https://github.com/uzzzval/CVE-2020-17530)

### [CVE-2020-17530](CVE-2020-17530-CyborgSecurity_CVE-2020-17530.md) 🔴

**名称:** CVE-2020-17530-Apache Struts-远程代码执行
**类型:** 远程代码执行 | **POC:** 是 | **投毒风险:** 0%
**仓库:** [CVE-2020-17530](https://github.com/CyborgSecurity/CVE-2020-17530)

### [CVE-2020-17530](CVE-2020-17530-Al1ex_CVE-2020-17530.md) 🔴

**名称:** CVE-2020-17530 Apache Struts OGNL 远程代码执行
**类型:** 远程代码执行 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [CVE-2020-17530](https://github.com/Al1ex/CVE-2020-17530)

### [CVE-2020-17530](CVE-2020-17530-ludy-dev_freemarker_RCE_struts2_s2-061.md) 🔴

**名称:** CVE-2020-17530-Apache Struts-OGNL远程代码执行
**类型:** 远程代码执行 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [freemarker_RCE_struts2_s2-061](https://github.com/ludy-dev/freemarker_RCE_struts2_s2-061)

### [CVE-2020-17530](CVE-2020-17530-wuzuowei_CVE-2020-17530.md) 🔴

**名称:** CVE-2020-17530-Apache Struts-远程代码执行
**类型:** 远程代码执行 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [CVE-2020-17530](https://github.com/wuzuowei/CVE-2020-17530)

### [CVE-2020-17530](CVE-2020-17530-fengziHK_CVE-2020-17530-strust2-061.md) 🔴

**名称:** CVE-2020-17530-Apache Struts-远程代码执行
**类型:** 远程代码执行 | **POC:** 是 | **投毒风险:** 1%
**仓库:** [CVE-2020-17530-strust2-061](https://github.com/fengziHK/CVE-2020-17530-strust2-061)

### [CVE-2020-17530](CVE-2020-17530-ka1n4t_CVE-2020-17530.md) 🔴

**名称:** CVE-2020-17530-Apache Struts-远程代码执行
**类型:** 远程代码执行 | **POC:** 是 | **投毒风险:** 0%
**仓库:** [CVE-2020-17530](https://github.com/ka1n4t/CVE-2020-17530)

### [CVE-2020-17530](CVE-2020-17530-phil-fly_CVE-2020-17530.md) 🔴

**名称:** CVE-2020-17530-Apache Struts2-远程代码执行
**类型:** 远程代码执行 | **POC:** 是 | **投毒风险:** 60%
**仓库:** [CVE-2020-17530](https://github.com/phil-fly/CVE-2020-17530)

### [CVE-2020-17530](CVE-2020-17530-secpool2000_CVE-2020-17530.md) 🔴 ⚠️

**名称:** CVE-2020-17530-Apache Struts2-OGNL表达式注入
**类型:** OGNL表达式注入 | **POC:** 是，但提供的POC无效 | **投毒风险:** 100%
**仓库:** [CVE-2020-17530](https://github.com/secpool2000/CVE-2020-17530)

### [CVE-2020-17530](CVE-2020-17530-nth347_CVE-2020-17530.md) 🔴

**名称:** CVE-2020-17530 - Apache Struts OGNL 远程代码执行
**类型:** 远程代码执行 (RCE) | **POC:** 是 | **投毒风险:** 10%
**仓库:** [CVE-2020-17530](https://github.com/nth347/CVE-2020-17530)

### [CVE-2020-17530](CVE-2020-17530-fatkz_CVE-2020-17530.md) 🔴

**名称:** CVE-2020-17530-Apache Struts2-OGNL注入
**类型:** OGNL注入 | **POC:** 是 | **投毒风险:** 1%
**仓库:** [CVE-2020-17530](https://github.com/fatkz/CVE-2020-17530)

### [CVE-2020-17519](CVE-2020-17519-dev-team-12x_CVE-2020-17519.md) 🔴

**名称:** CVE-2020-17519 - Apache Flink 目录遍历
**类型:** 目录遍历/文件读取 | **POC:** 是 | **投毒风险:** 0%
**仓库:** [CVE-2020-17519](https://github.com/dev-team-12x/CVE-2020-17519)

### [CVE-2020-17519](CVE-2020-17519-GazettEl_CVE-2020-17519.md) 🔴

**名称:** CVE-2020-17519-Apache Flink目录遍历
**类型:** 目录遍历 | **POC:** 是 | **投毒风险:** 1%
**仓库:** [CVE-2020-17519](https://github.com/GazettEl/CVE-2020-17519)

### [CVE-2020-17519](CVE-2020-17519-zhangweijie11_CVE-2020-17519.md) 🔴

**名称:** CVE-2020-17519-Apache Flink目录遍历
**类型:** 目录遍历 | **POC:** 是 | **投毒风险:** 0%
**仓库:** [CVE-2020-17519](https://github.com/zhangweijie11/CVE-2020-17519)

### [CVE-2020-17519](CVE-2020-17519-givemefivw_CVE-2020-17519.md) 🔴

**名称:** CVE-2020-17519 Apache Flink 任意文件读取
**类型:** 目录遍历/文件读取 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [CVE-2020-17519](https://github.com/givemefivw/CVE-2020-17519)

### [CVE-2020-17519](CVE-2020-17519-Osyanina_westone-CVE-2020-17519-scanner.md) 🔴

**名称:** CVE-2020-17519-Apache Flink 目录遍历
**类型:** 目录遍历 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [westone-CVE-2020-17519-scanner](https://github.com/Osyanina/westone-CVE-2020-17519-scanner)

### [CVE-2020-17519](CVE-2020-17519-radbsie_CVE-2020-17519-Exp.md) 🔴

**名称:** CVE-2020-17519-Apache Flink-目录遍历
**类型:** 目录遍历 | **POC:** 是 | **投毒风险:** 0%
**仓库:** [CVE-2020-17519-Exp](https://github.com/radbsie/CVE-2020-17519-Exp)

### [CVE-2020-17519](CVE-2020-17519-murataydemir_CVE-2020-17519.md) 🔴

**名称:** CVE-2020-17519 - Apache Flink RESTful API 任意文件读取
**类型:** 目录遍历 | **POC:** 是 | **投毒风险:** 1%
**仓库:** [CVE-2020-17519](https://github.com/murataydemir/CVE-2020-17519)

### [CVE-2020-17519](CVE-2020-17519-B1anda0_CVE-2020-17519.md) 🔴

**名称:** CVE-2020-17519-Apache Flink 目录遍历
**类型:** 目录遍历 | **POC:** 是 | **投毒风险:** 0%
**仓库:** [CVE-2020-17519](https://github.com/B1anda0/CVE-2020-17519)

### [CVE-2020-17519](CVE-2020-17519-dolevf_apache-flink-directory-traversal.nse.md) 🔴

**名称:** CVE-2020-17519-Apache Flink 目录遍历
**类型:** 目录遍历 | **POC:** 是 | **投毒风险:** 0%
**仓库:** [apache-flink-directory-traversal.nse](https://github.com/dolevf/apache-flink-directory-traversal.nse)

### [CVE-2020-17519](CVE-2020-17519-QmF0c3UK_CVE-2020-17519.md) 🔴

**名称:** CVE-2020-17519-Apache Flink-目录遍历
**类型:** 目录遍历 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [CVE-2020-17519](https://github.com/QmF0c3UK/CVE-2020-17519)

### [CVE-2020-17519](CVE-2020-17519-yaunsky_CVE-2020-17519-Apache-Flink.md) 🔴

**名称:** CVE-2020-17519-Apache Flink 目录遍历
**类型:** 目录遍历 | **POC:** 是 | **投毒风险:** 0%
**仓库:** [CVE-2020-17519-Apache-Flink](https://github.com/yaunsky/CVE-2020-17519-Apache-Flink)

### [CVE-2020-17519](CVE-2020-17519-shoucheng3_apache__flink_CVE-2020-17519_1-11-2.md) 🔴

**名称:** CVE-2020-17519-Apache Flink-目录遍历
**类型:** 目录遍历 | **POC:** 是 | **投毒风险:** 0%
**仓库:** [apache__flink_CVE-2020-17519_1-11-2](https://github.com/shoucheng3/apache__flink_CVE-2020-17519_1-11-2)

### [CVE-2020-16898](CVE-2020-16898-ZephrFish_CVE-2020-16898.md) 🔴 ⚠️

**名称:** CVE-2020-16898 Bad Neighbor
**类型:** 远程代码执行 | **POC:** 是 | **投毒风险:** 70%
**仓库:** [CVE-2020-16898](https://github.com/ZephrFish/CVE-2020-16898)

### [CVE-2020-16898](CVE-2020-16898-corelight_CVE-2020-16898.md) 🔴

**名称:** CVE-2020-16898 - Windows TCP/IP 远程代码执行漏洞（Bad Neighbor）
**类型:** 远程代码执行（RCE） | **POC:** 是 | **投毒风险:** 5%
**仓库:** [CVE-2020-16898](https://github.com/corelight/CVE-2020-16898)

### [CVE-2020-16898](CVE-2020-16898-komomon_CVE-2020-16898--EXP-POC.md) 🔴

**名称:** CVE-2020-16898 Windows TCP/IP 远程代码执行漏洞
**类型:** 远程代码执行 | **POC:** 是 | **投毒风险:** 5%
**仓库:** [CVE-2020-16898--EXP-POC](https://github.com/komomon/CVE-2020-16898--EXP-POC)

### [CVE-2020-16898](CVE-2020-16898-komomon_CVE-2020-16898-EXP-POC.md) 🔴

**名称:** CVE-2020-16898 Windows TCP/IP 远程代码执行漏洞
**类型:** 远程代码执行 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [CVE-2020-16898-EXP-POC](https://github.com/komomon/CVE-2020-16898-EXP-POC)

### [CVE-2020-16898](CVE-2020-16898-advanced-threat-research_CVE-2020-16898.md) 🔴

**名称:** CVE-2020-16898: Windows TCP/IP 远程代码执行漏洞 ("Bad Neighbor")
**类型:** 远程代码执行 (RCE) | **POC:** 是 | **投毒风险:** 1%
**仓库:** [CVE-2020-16898](https://github.com/advanced-threat-research/CVE-2020-16898)

### [CVE-2020-16898](CVE-2020-16898-initconf_CVE-2020-16898-Bad-Neighbor.md) 🔴

**名称:** CVE-2020-16898: Bad Neighbor - Windows TCP/IP远程代码执行漏洞
**类型:** 远程代码执行 (RCE) | **POC:** 是 | **投毒风险:** 10%
**仓库:** [CVE-2020-16898-Bad-Neighbor](https://github.com/initconf/CVE-2020-16898-Bad-Neighbor)

### [CVE-2020-16898](CVE-2020-16898-CPO-EH_CVE-2020-16898_Checker.md) 🔴

**名称:** CVE-2020-16898 "Bad Neighbor" Windows TCP/IP 远程代码执行漏洞
**类型:** 远程代码执行 | **POC:** 是，但提供的代码仅为检测脚本 | **投毒风险:** 0%
**仓库:** [CVE-2020-16898_Checker](https://github.com/CPO-EH/CVE-2020-16898_Checker)

### [CVE-2020-16898](CVE-2020-16898-CPO-EH_CVE-2020-16898_Workaround.md) 🔴

**名称:** CVE-2020-16898
**类型:** 远程代码执行 (RCE) | **POC:** 是，存在利用代码，可触发蓝屏 (BSOD)。 | **投毒风险:** 0%
**仓库:** [CVE-2020-16898_Workaround](https://github.com/CPO-EH/CVE-2020-16898_Workaround)

### [CVE-2020-16898](CVE-2020-16898-momika233_CVE-2020-16898-exp.md) 🔴

**名称:** CVE-2020-16898 - Windows TCP/IP 远程代码执行漏洞（Bad Neighbor）
**类型:** 远程代码执行 (RCE) | **POC:** 是 | **投毒风险:** 5%
**仓库:** [CVE-2020-16898-exp](https://github.com/momika233/CVE-2020-16898-exp)

### [CVE-2020-16898](CVE-2020-16898-jiansiting_cve-2020-16898.md) 🔴

**名称:** CVE-2020-16898 Bad Neighbor
**类型:** 远程代码执行 | **POC:** 是 | **投毒风险:** 0%
**仓库:** [cve-2020-16898](https://github.com/jiansiting/cve-2020-16898)

### [CVE-2020-16898](CVE-2020-16898-0xeb-bp_cve-2020-16898.md) 🔴

**名称:** CVE-2020-16898-Windows TCP/IP远程代码执行
**类型:** 远程代码执行 (RCE) | **POC:** 是 | **投毒风险:** 10%
**仓库:** [cve-2020-16898](https://github.com/0xeb-bp/cve-2020-16898)

### [CVE-2020-16898](CVE-2020-16898-Q1984_CVE-2020-16898.md) 🔴

**名称:** CVE-2020-16898 Bad Neighbor
**类型:** 远程代码执行/拒绝服务 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [CVE-2020-16898](https://github.com/Q1984/CVE-2020-16898)

### [CVE-2020-16898](CVE-2020-16898-Maliek_CVE-2020-16898_Check.md) 🔴

**名称:** CVE-2020-16898 "Bad Neighbor"
**类型:** 远程代码执行 | **POC:** 是 | **投毒风险:** 0%
**仓库:** [CVE-2020-16898_Check](https://github.com/Maliek/CVE-2020-16898_Check)

### [CVE-2020-16898](CVE-2020-16898-esnet-security_cve-2020-16898.md) 🔴

**名称:** CVE-2020-16898 - Windows TCP/IP 远程代码执行漏洞 (Bad Neighbor)
**类型:** 远程代码执行 (RCE) | **POC:** 是，网络上已存在公开的PoC | **投毒风险:** 10%
**仓库:** [cve-2020-16898](https://github.com/esnet-security/cve-2020-16898)

### [CVE-2020-16012](CVE-2020-16012-helidem_CVE-2020-16012-PoC.md)

**名称:** CVE-2020-16012-Chrome-侧信道信息泄露
**类型:** 侧信道信息泄露 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [CVE-2020-16012-PoC](https://github.com/helidem/CVE-2020-16012-PoC)

### [CVE-2020-16012](CVE-2020-16012-aleksejspopovs_cve-2020-16012.md)

**名称:** CVE-2020-16012-Chrome-侧信道信息泄露
**类型:** 侧信道信息泄露 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [cve-2020-16012](https://github.com/aleksejspopovs/cve-2020-16012)

### [CVE-2020-15778](CVE-2020-15778-drackyjr_CVE-2020-15778-SCP-Command-Injection-Check.md) 🔴

**名称:** CVE-2020-15778-OpenSSH-SCP命令注入
**类型:** 命令注入 | **POC:** 是 | **投毒风险:** 0%
**仓库:** [CVE-2020-15778-SCP-Command-Injection-Check](https://github.com/drackyjr/CVE-2020-15778-SCP-Command-Injection-Check)

### [CVE-2020-15778](CVE-2020-15778-Evan-Zhangyf_CVE-2020-15778.md) 🔴

**名称:** CVE-2020-15778 OpenSSH SCP 命令注入
**类型:** 命令注入 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [CVE-2020-15778](https://github.com/Evan-Zhangyf/CVE-2020-15778)

### [CVE-2020-15778](CVE-2020-15778-cpandya2909_CVE-2020-15778.md) 🔴

**名称:** CVE-2020-15778 OpenSSH SCP 命令注入
**类型:** 命令注入 | **POC:** 是 | **投毒风险:** 1%
**仓库:** [CVE-2020-15778](https://github.com/cpandya2909/CVE-2020-15778)

### [CVE-2020-15778](CVE-2020-15778-Neko-chanQwQ_CVE-2020-15778-Exploit.md) 🔴

**名称:** CVE-2020-15778-OpenSSH-命令注入
**类型:** 命令注入 | **POC:** 是 | **投毒风险:** 0%
**仓库:** [CVE-2020-15778-Exploit](https://github.com/Neko-chanQwQ/CVE-2020-15778-Exploit)

### [CVE-2020-14883](CVE-2020-14883-amacloudobia_CVE-2020-14883.md) 🔴

**名称:** CVE-2020-14883-WebLogic-RCE
**类型:** 远程代码执行 | **POC:** 是 | **投毒风险:** 0%
**仓库:** [CVE-2020-14883](https://github.com/amacloudobia/CVE-2020-14883)

### [CVE-2020-14883](CVE-2020-14883-Osyanina_westone-CVE-2020-14883-scanner.md) 🔴

**名称:** CVE-2020-14883-Oracle WebLogic Server 远程代码执行
**类型:** 远程代码执行 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [westone-CVE-2020-14883-scanner](https://github.com/Osyanina/westone-CVE-2020-14883-scanner)

### [CVE-2020-14883](CVE-2020-14883-fan1029_CVE-2020-14883EXP.md) 🔴

**名称:** CVE-2020-14883-Oracle WebLogic Server-远程代码执行
**类型:** 远程代码执行 | **POC:** 是 | **投毒风险:** 5%
**仓库:** [CVE-2020-14883EXP](https://github.com/fan1029/CVE-2020-14883EXP)

### [CVE-2020-14883](CVE-2020-14883-B1anda0_CVE-2020-14883.md) 🔴

**名称:** CVE-2020-14883 WebLogic 身份验证绕过
**类型:** 身份验证绕过 | **POC:** 是 | **投毒风险:** 1%
**仓库:** [CVE-2020-14883](https://github.com/B1anda0/CVE-2020-14883)

### [CVE-2020-14883](CVE-2020-14883-murataydemir_CVE-2020-14883.md) 🔴

**名称:** CVE-2020-14883 - Oracle WebLogic Server 远程代码执行
**类型:** 远程代码执行 (RCE) | **POC:** 是 | **投毒风险:** 0%
**仓库:** [CVE-2020-14883](https://github.com/murataydemir/CVE-2020-14883)

### [CVE-2020-14883](CVE-2020-14883-B1ack4sh_Blackash-CVE-2020-14883.md) 🔴

**名称:** CVE-2020-14883 - Oracle WebLogic Server RCE
**类型:** 远程代码执行 (RCE) | **POC:** 是 | **投毒风险:** 5%
**仓库:** [Blackash-CVE-2020-14883](https://github.com/B1ack4sh/Blackash-CVE-2020-14883)

### [CVE-2020-14882](CVE-2020-14882-AleksaZatezalo_CVE-2020-14882.md) 🔴

**名称:** CVE-2020-14882-Oracle WebLogic Server-远程代码执行
**类型:** 远程代码执行 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [CVE-2020-14882](https://github.com/AleksaZatezalo/CVE-2020-14882)

### [CVE-2020-14882](CVE-2020-14882-Root-Shells_CVE-2020-14882.md) 🔴

**名称:** CVE-2020-14882-Oracle WebLogic-RCE
**类型:** 远程代码执行 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [CVE-2020-14882](https://github.com/Root-Shells/CVE-2020-14882)

### [CVE-2020-14882](CVE-2020-14882-zesnd_CVE-2020-14882-POC.md) 🔴

**名称:** CVE-2020-14882-Oracle WebLogic Server-远程代码执行
**类型:** 远程代码执行 | **POC:** 是 | **投毒风险:** 0%
**仓库:** [CVE-2020-14882-POC](https://github.com/zesnd/CVE-2020-14882-POC)

### [CVE-2020-14882](CVE-2020-14882-LucasPDiniz_CVE-2020-14882.md) 🔴

**名称:** CVE-2020-14882 - Oracle WebLogic RCE
**类型:** 远程代码执行 (RCE) | **POC:** 是 | **投毒风险:** 5%
**仓库:** [CVE-2020-14882](https://github.com/LucasPDiniz/CVE-2020-14882)

### [CVE-2020-14882](CVE-2020-14882-xMr110_CVE-2020-14882.md) 🔴

**名称:** CVE-2020-14882-Oracle WebLogic Server-RCE
**类型:** 远程代码执行 | **POC:** 是 | **投毒风险:** 5%
**仓库:** [CVE-2020-14882](https://github.com/xMr110/CVE-2020-14882)

### [CVE-2020-14882](CVE-2020-14882-Danny-LLi_CVE-2020-14882.md) 🔴

**名称:** CVE-2020-14882 Oracle WebLogic Server 远程代码执行
**类型:** 远程代码执行 (RCE) | **POC:** 是 | **投毒风险:** 1%
**仓库:** [CVE-2020-14882](https://github.com/Danny-LLi/CVE-2020-14882)

### [CVE-2020-14882](CVE-2020-14882-GGyao_CVE-2020-14882_ALL.md) 🔴

**名称:** CVE-2020-14882-Oracle WebLogic Server-远程代码执行
**类型:** 远程代码执行 | **POC:** 是 | **投毒风险:** 0%
**仓库:** [CVE-2020-14882_ALL](https://github.com/GGyao/CVE-2020-14882_ALL)

### [CVE-2020-14882](CVE-2020-14882-N0Coriander_CVE-2020-14882-14883.md) 🔴

**名称:** CVE-2020-14882/CVE-2020-14883 WebLogic 未授权远程代码执行
**类型:** 远程代码执行 | **POC:** 是 | **投毒风险:** 0%
**仓库:** [CVE-2020-14882-14883](https://github.com/N0Coriander/CVE-2020-14882-14883)

### [CVE-2020-14882](CVE-2020-14882-qianniaoge_CVE-2020-14882_Exploit_Gui.md) 🔴

**名称:** CVE-2020-14882-Oracle WebLogic Server RCE
**类型:** 远程代码执行 (RCE) | **POC:** 是 | **投毒风险:** 10%
**仓库:** [CVE-2020-14882_Exploit_Gui](https://github.com/qianniaoge/CVE-2020-14882_Exploit_Gui)

### [CVE-2020-14882](CVE-2020-14882-zhzyker_exphub.md) 🔴

**名称:** CVE-2020-14882 - Oracle WebLogic Server 未授权远程命令执行
**类型:** 远程命令执行 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [exphub](https://github.com/zhzyker/exphub)

### [CVE-2020-14882](CVE-2020-14882-milo2012_CVE-2020-14882.md) 🔴

**名称:** CVE-2020-14882-Oracle WebLogic Server-远程代码执行
**类型:** 远程代码执行 | **POC:** 是 | **投毒风险:** 1%
**仓库:** [CVE-2020-14882](https://github.com/milo2012/CVE-2020-14882)

### [CVE-2020-14882](CVE-2020-14882-pwn3z_CVE-2020-14882-WebLogic.md) 🔴

**名称:** CVE-2020-14882-Oracle WebLogic Server 远程代码执行
**类型:** 远程代码执行 (RCE) | **POC:** 是 | **投毒风险:** 10%
**仓库:** [CVE-2020-14882-WebLogic](https://github.com/pwn3z/CVE-2020-14882-WebLogic)

### [CVE-2020-14882](CVE-2020-14882-kk98kk0_CVE-2020-14882.md) 🔴

**名称:** CVE-2020-14882-Oracle WebLogic Server-远程代码执行
**类型:** 远程代码执行 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [CVE-2020-14882](https://github.com/kk98kk0/CVE-2020-14882)

### [CVE-2020-14882](CVE-2020-14882-adm1in_CodeTest.md) 🔴

**名称:** CVE-2020-14882-Oracle WebLogic Server远程代码执行
**类型:** 远程代码执行 (RCE) | **POC:** 是 | **投毒风险:** 20%
**仓库:** [CodeTest](https://github.com/adm1in/CodeTest)

### [CVE-2020-14882](CVE-2020-14882-corelight_CVE-2020-14882-weblogicRCE.md) 🔴

**名称:** CVE-2020-14882 - Oracle WebLogic RCE
**类型:** 远程代码执行 (RCE) | **POC:** 是 | **投毒风险:** 5%
**仓库:** [CVE-2020-14882-weblogicRCE](https://github.com/corelight/CVE-2020-14882-weblogicRCE)

### [CVE-2020-14882](CVE-2020-14882-jas502n_CVE-2020-14882.md) 🔴

**名称:** CVE-2020-14882 WebLogic 未授权绕过RCE
**类型:** 远程代码执行 (RCE) | **POC:** 是 | **投毒风险:** 10%
**仓库:** [CVE-2020-14882](https://github.com/jas502n/CVE-2020-14882)

### [CVE-2020-14882](CVE-2020-14882-xfiftyone_CVE-2020-14882.md) 🔴

**名称:** CVE-2020-14882-Oracle WebLogic Server 远程代码执行
**类型:** 远程代码执行 (RCE) | **POC:** 是 | **投毒风险:** 10%
**仓库:** [CVE-2020-14882](https://github.com/xfiftyone/CVE-2020-14882)

### [CVE-2020-14882](CVE-2020-14882-QmF0c3UK_CVE-2020-14882.md) 🔴

**名称:** CVE-2020-14882-Oracle WebLogic Server-RCE
**类型:** 远程代码执行 (RCE) | **POC:** 是 | **投毒风险:** 10%
**仓库:** [CVE-2020-14882](https://github.com/QmF0c3UK/CVE-2020-14882)

### [CVE-2020-14882](CVE-2020-14882-Ormicron_CVE-2020-14882-GUI-Test.md) 🔴

**名称:** CVE-2020-14882-Oracle WebLogic Server 远程代码执行
**类型:** 远程代码执行 (RCE) | **POC:** 是 | **投毒风险:** 10%
**仓库:** [CVE-2020-14882-GUI-Test](https://github.com/Ormicron/CVE-2020-14882-GUI-Test)

### [CVE-2020-14882](CVE-2020-14882-nik0nz7_CVE-2020-14882.md) 🔴

**名称:** CVE-2020-14882 - Oracle WebLogic Server RCE
**类型:** 远程代码执行 (RCE) | **POC:** 是 | **投毒风险:** 5%
**仓库:** [CVE-2020-14882](https://github.com/nik0nz7/CVE-2020-14882)

### [CVE-2020-14882](CVE-2020-14882-exploitblizzard_CVE-2020-14882-WebLogic.md) 🔴

**名称:** CVE-2020-14882 WebLogic Console RCE
**类型:** 远程代码执行 (RCE) | **POC:** 是 | **投毒风险:** 0%
**仓库:** [CVE-2020-14882-WebLogic](https://github.com/exploitblizzard/CVE-2020-14882-WebLogic)

### [CVE-2020-14882](CVE-2020-14882-GGyao_CVE-2020-14882_POC.md) 🔴

**名称:** CVE-2020-14882 - Oracle WebLogic Server 远程代码执行
**类型:** 远程代码执行 (RCE) | **POC:** 是 | **投毒风险:** 10%
**仓库:** [CVE-2020-14882_POC](https://github.com/GGyao/CVE-2020-14882_POC)

### [CVE-2020-14882](CVE-2020-14882-AshrafZaryouh_CVE-2020-14882.md) 🔴

**名称:** CVE-2020-14882 - Oracle WebLogic Server 远程代码执行
**类型:** 远程代码执行 (RCE) | **POC:** 是 | **投毒风险:** 10%
**仓库:** [CVE-2020-14882](https://github.com/AshrafZaryouh/CVE-2020-14882)

### [CVE-2020-14882](CVE-2020-14882-B1ack4sh_Blackash-CVE-2020-14882.md) 🔴

**名称:** CVE-2020-14882 - Oracle WebLogic Server RCE (Unauthenticated)
**类型:** 远程代码执行 (RCE) | **POC:** 是 | **投毒风险:** 10%
**仓库:** [Blackash-CVE-2020-14882](https://github.com/B1ack4sh/Blackash-CVE-2020-14882)

### [CVE-2020-1472](CVE-2020-1472-tdevworks_CVE-2020-1472-ZeroLogon-Demo-Detection-Mitigation.md) 🔴

**名称:** CVE-2020-1472 (Zerologon) Netlogon 权限提升漏洞
**类型:** 权限提升 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [CVE-2020-1472-ZeroLogon-Demo-Detection-Mitigation](https://github.com/tdevworks/CVE-2020-1472-ZeroLogon-Demo-Detection-Mitigation)

### [CVE-2020-1472](CVE-2020-1472-TuanCui22_ZerologonWithImpacket-CVE2020-1472.md) 🔴

**名称:** CVE-2020-1472 (Zerologon)
**类型:** 特权提升 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [ZerologonWithImpacket-CVE2020-1472](https://github.com/TuanCui22/ZerologonWithImpacket-CVE2020-1472)

### [CVE-2020-1472](CVE-2020-1472-blackh00d_zerologon-poc.md) 🔴

**名称:** CVE-2020-1472 Zerologon Netlogon 特权提升漏洞
**类型:** 特权提升 | **POC:** 是 | **投毒风险:** 1%
**仓库:** [zerologon-poc](https://github.com/blackh00d/zerologon-poc)

### [CVE-2020-1472](CVE-2020-1472-JolynNgSC_Zerologon_CVE-2020-1472.md) 🔴

**名称:** CVE-2020-1472 Netlogon Elevation of Privilege Vulnerability (Zerologon)
**类型:** 权限提升 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [Zerologon_CVE-2020-1472](https://github.com/JolynNgSC/Zerologon_CVE-2020-1472)

### [CVE-2020-1472](CVE-2020-1472-whoami-chmod777_Zerologon-Attack-CVE-2020-1472-POC.md) 🔴

**名称:** CVE-2020-1472 (Zerologon)
**类型:** 权限提升 | **POC:** 是 | **投毒风险:** 5%
**仓库:** [Zerologon-Attack-CVE-2020-1472-POC](https://github.com/whoami-chmod777/Zerologon-Attack-CVE-2020-1472-POC)

### [CVE-2020-1472](CVE-2020-1472-logg-1_0logon.md) 🔴

**名称:** CVE-2020-1472 (Zerologon)
**类型:** 权限提升 | **POC:** 是 | **投毒风险:** 0%
**仓库:** [0logon](https://github.com/logg-1/0logon)

### [CVE-2020-1472](CVE-2020-1472-c3rrberu5_ZeroLogon-to-Shell.md) 🔴

**名称:** CVE-2020-1472 Zerologon权限提升漏洞
**类型:** 权限提升 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [ZeroLogon-to-Shell](https://github.com/c3rrberu5/ZeroLogon-to-Shell)

### [CVE-2020-1472](CVE-2020-1472-SecuraBV_CVE-2020-1472.md) 🔴

**名称:** CVE-2020-1472 - Netlogon Elevation of Privilege Vulnerability (Zerologon)
**类型:** 权限提升 | **POC:** 是 | **投毒风险:** 5%
**仓库:** [CVE-2020-1472](https://github.com/SecuraBV/CVE-2020-1472)

### [CVE-2020-1472](CVE-2020-1472-zeronetworks_zerologon.md) 🔴

**名称:** CVE-2020-1472 Zerologon 本地提权漏洞
**类型:** 特权提升 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [zerologon](https://github.com/zeronetworks/zerologon)

### [CVE-2020-1472](CVE-2020-1472-Akash7350_CVE-2020-1472.md) 🔴

**名称:** CVE-2020-1472-Zerologon-特权提升
**类型:** 特权提升 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [CVE-2020-1472](https://github.com/Akash7350/CVE-2020-1472)

### [CVE-2020-1472](CVE-2020-1472-bb00_zer0dump.md) 🔴

**名称:** CVE-2020-1472 (Zerologon) 权限提升漏洞
**类型:** 权限提升 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [zer0dump](https://github.com/bb00/zer0dump)

### [CVE-2020-1472](CVE-2020-1472-sv3nbeast_CVE-2020-1472.md) 🔴

**名称:** CVE-2020-1472 (Zerologon) Netlogon 特权提升漏洞
**类型:** 特权提升 | **POC:** 是 | **投毒风险:** 1%
**仓库:** [CVE-2020-1472](https://github.com/sv3nbeast/CVE-2020-1472)

### [CVE-2020-1472](CVE-2020-1472-dr4g0n23_CVE-2020-1472.md) 🔴

**名称:** CVE-2020-1472 Zerologon 本地提权漏洞
**类型:** 权限提升 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [CVE-2020-1472](https://github.com/dr4g0n23/CVE-2020-1472)

### [CVE-2020-1472](CVE-2020-1472-guglia001_MassZeroLogon.md) 🔴

**名称:** CVE-2020-1472-Zerologon
**类型:** 权限提升 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [MassZeroLogon](https://github.com/guglia001/MassZeroLogon)

### [CVE-2020-1472](CVE-2020-1472-likeww_MassZeroLogon.md) 🔴

**名称:** CVE-2020-1472 (Zerologon) Netlogon 特权提升漏洞
**类型:** 特权提升 | **POC:** 是 | **投毒风险:** 5%
**仓库:** [MassZeroLogon](https://github.com/likeww/MassZeroLogon)

### [CVE-2020-1472](CVE-2020-1472-Rvn0xsy_ZeroLogon.md) 🔴

**名称:** CVE-2020-1472 Zerologon
**类型:** 权限提升 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [ZeroLogon](https://github.com/Rvn0xsy/ZeroLogon)

### [CVE-2020-1472](CVE-2020-1472-sho-luv_zerologon.md) 🔴

**名称:** CVE-2020-1472 Zerologon
**类型:** 权限提升 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [zerologon](https://github.com/sho-luv/zerologon)

### [CVE-2020-1472](CVE-2020-1472-B34MR_zeroscan.md) 🔴

**名称:** CVE-2020-1472 (Zerologon)
**类型:** 权限提升 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [zeroscan](https://github.com/B34MR/zeroscan)

### [CVE-2020-1472](CVE-2020-1472-carlos55ml_zerologon.md) 🔴

**名称:** CVE-2020-1472 Zerologon Netlogon特权提升漏洞
**类型:** 特权提升 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [zerologon](https://github.com/carlos55ml/zerologon)

### [CVE-2020-1472](CVE-2020-1472-Anonymous-Family_Zero-day-scanning.md) 🔴

**名称:** CVE-2020-1472 Zerologon 权限提升漏洞
**类型:** 权限提升 | **POC:** 是 | **投毒风险:** 5%
**仓库:** [Zero-day-scanning](https://github.com/Anonymous-Family/Zero-day-scanning)

### [CVE-2020-1472](CVE-2020-1472-TheJoyOfHacking_dirkjanm-CVE-2020-1472.md) 🔴

**名称:** CVE-2020-1472 (Zerologon)
**类型:** 权限提升 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [dirkjanm-CVE-2020-1472](https://github.com/TheJoyOfHacking/dirkjanm-CVE-2020-1472)

### [CVE-2020-1472](CVE-2020-1472-TheJoyOfHacking_SecuraBV-CVE-2020-1472.md) 🔴

**名称:** CVE-2020-1472 (Zerologon): Netlogon 特权提升漏洞
**类型:** 特权提升 | **POC:** 是 | **投毒风险:** 1%
**仓库:** [SecuraBV-CVE-2020-1472](https://github.com/TheJoyOfHacking/SecuraBV-CVE-2020-1472)

### [CVE-2020-1472](CVE-2020-1472-CPO-EH_CVE-2020-1472_ZeroLogonChecker.md) 🔴

**名称:** CVE-2020-1472 (Zerologon) 漏洞检测
**类型:** 权限提升 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [CVE-2020-1472_ZeroLogonChecker](https://github.com/CPO-EH/CVE-2020-1472_ZeroLogonChecker)

### [CVE-2020-1472](CVE-2020-1472-Fa1c0n35_SecuraBV-CVE-2020-1472.md) 🔴

**名称:** CVE-2020-1472 Zerologon 本地提权漏洞
**类型:** 权限提升 | **POC:** 是 | **投毒风险:** 5%
**仓库:** [SecuraBV-CVE-2020-1472](https://github.com/Fa1c0n35/SecuraBV-CVE-2020-1472)

### [CVE-2020-1472](CVE-2020-1472-Fa1c0n35_CVE-2020-1472-02-.md) 🔴

**名称:** CVE-2020-1472 (Zerologon)
**类型:** 权限提升 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [CVE-2020-1472-02-](https://github.com/Fa1c0n35/CVE-2020-1472-02-)

### [CVE-2020-1472](CVE-2020-1472-puckiestyle_CVE-2020-1472.md) 🔴

**名称:** CVE-2020-1472 (Zerologon) Netlogon 权限提升漏洞
**类型:** 权限提升 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [CVE-2020-1472](https://github.com/puckiestyle/CVE-2020-1472)

### [CVE-2020-1472](CVE-2020-1472-itssmikefm_CVE-2020-1472.md) 🔴

**名称:** CVE-2020-1472 Zerologon 权限提升漏洞
**类型:** 权限提升 | **POC:** 是 | **投毒风险:** 5%
**仓库:** [CVE-2020-1472](https://github.com/itssmikefm/CVE-2020-1472)

### [CVE-2020-1472](CVE-2020-1472-PakwanSK_Simulating-and-preventing-Zerologon-CVE-2020-1472-vulnerability-attacks..md) 🔴

**名称:** CVE-2020-1472 (Zerologon)
**类型:** 权限提升 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [Simulating-and-preventing-Zerologon-CVE-2020-1472-vulnerability-attacks.](https://github.com/PakwanSK/Simulating-and-preventing-Zerologon-CVE-2020-1472-vulnerability-attacks.)

### [CVE-2020-1472](CVE-2020-1472-RicYaben_CVE-2020-1472-LAB.md) 🔴

**名称:** CVE-2020-1472 Zerologon Netlogon 权限提升漏洞
**类型:** 权限提升 | **POC:** 是 | **投毒风险:** 1%
**仓库:** [CVE-2020-1472-LAB](https://github.com/RicYaben/CVE-2020-1472-LAB)

### [CVE-2020-1472](CVE-2020-1472-Anonymous-Family_CVE-2020-1472.md) 🔴

**名称:** CVE-2020-1472 Zerologon 特权提升漏洞
**类型:** 特权提升 | **POC:** 是 | **投毒风险:** 0%
**仓库:** [CVE-2020-1472](https://github.com/Anonymous-Family/CVE-2020-1472)

### [CVE-2020-1472](CVE-2020-1472-100HnoMeuNome_ZeroLogon-CVE-2020-1472-lab.md) 🔴

**名称:** CVE-2020-1472 Zerologon
**类型:** 权限提升 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [ZeroLogon-CVE-2020-1472-lab](https://github.com/100HnoMeuNome/ZeroLogon-CVE-2020-1472-lab)

### [CVE-2020-14343](CVE-2020-14343-Kairo-one_CVE-2020-14343.md) 🔴

**名称:** CVE-2020-14343-PyYAML反序列化漏洞
**类型:** 反序列化漏洞 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [CVE-2020-14343](https://github.com/Kairo-one/CVE-2020-14343)

### [CVE-2020-14343](CVE-2020-14343-j4k0m_loader-CVE-2020-14343.md) 🔴

**名称:** CVE-2020-14343-PyYAML-任意代码执行
**类型:** 任意代码执行 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [loader-CVE-2020-14343](https://github.com/j4k0m/loader-CVE-2020-14343)

### [CVE-2020-14008](CVE-2020-14008-JackHars_cve-2020-14008.md) 🔴

**名称:** CVE-2020-14008 Zoho ManageEngine Applications Manager RCE
**类型:** 远程代码执行 | **POC:** 是 | **投毒风险:** 0%
**仓库:** [cve-2020-14008](https://github.com/JackHars/cve-2020-14008)

### [CVE-2020-13973](CVE-2020-13973-shoucheng3_OWASP__json-sanitizer_CVE-2020-13973_1-2-0.md)

**名称:** CVE-2020-13973-OWASP json-sanitizer-XSS
**类型:** XSS | **POC:** 否 | **投毒风险:** 0%
**仓库:** [OWASP__json-sanitizer_CVE-2020-13973_1-2-0](https://github.com/shoucheng3/OWASP__json-sanitizer_CVE-2020-13973_1-2-0)

### [CVE-2020-13973](CVE-2020-13973-epicosy_json-sanitizer.md)

**名称:** CVE-2020-13973-OWASP json-sanitizer-XSS
**类型:** XSS | **POC:** 是 | **投毒风险:** 0%
**仓库:** [json-sanitizer](https://github.com/epicosy/json-sanitizer)

### [CVE-2020-13942](CVE-2020-13942-corsisechero_CVE-2020-13942byVulHub.md) 🔴

**名称:** CVE-2020-13942-Apache Unomi-RCE
**类型:** 远程代码执行 | **POC:** 是 | **投毒风险:** 1%
**仓库:** [CVE-2020-13942byVulHub](https://github.com/corsisechero/CVE-2020-13942byVulHub)

### [CVE-2020-13942](CVE-2020-13942-blackmarketer_CVE-2020-13942.md) 🔴

**名称:** CVE-2020-13942-Apache Unomi-RCE
**类型:** 远程代码执行(RCE) | **POC:** 是 | **投毒风险:** 0%
**仓库:** [CVE-2020-13942](https://github.com/blackmarketer/CVE-2020-13942)

### [CVE-2020-13942](CVE-2020-13942-Prodrious_CVE-2020-13942.md) 🔴

**名称:** CVE-2020-13942-Apache Unomi-远程代码执行
**类型:** 远程代码执行 | **POC:** 是 | **投毒风险:** 0%
**仓库:** [CVE-2020-13942](https://github.com/Prodrious/CVE-2020-13942)

### [CVE-2020-13942](CVE-2020-13942-hoanx4_apche_unomi_rce.md) 🔴

**名称:** CVE-2020-13942 - Apache Unomi Remote Code Execution
**类型:** Remote Code Execution (RCE) | **POC:** 是 | **投毒风险:** 1%
**仓库:** [apche_unomi_rce](https://github.com/hoanx4/apche_unomi_rce)

### [CVE-2020-13942](CVE-2020-13942-yaunsky_Unomi-CVE-2020-13942.md) 🔴

**名称:** CVE-2020-13942 Apache Unomi Remote Code Execution
**类型:** Remote Code Execution | **POC:** 是 | **投毒风险:** 0%
**仓库:** [Unomi-CVE-2020-13942](https://github.com/yaunsky/Unomi-CVE-2020-13942)

### [CVE-2020-13942](CVE-2020-13942-eugenebmx_CVE-2020-13942.md) 🔴

**名称:** CVE-2020-13942 - Apache Unomi RCE
**类型:** 远程代码执行 (RCE) | **POC:** 是 | **投毒风险:** 0%
**仓库:** [CVE-2020-13942](https://github.com/eugenebmx/CVE-2020-13942)

### [CVE-2020-13942](CVE-2020-13942-shifa123_CVE-2020-13942-POC-.md) 🔴

**名称:** CVE-2020-13942-Apache Unomi-远程代码执行
**类型:** 远程代码执行 (RCE) | **POC:** 是 | **投毒风险:** 0%
**仓库:** [CVE-2020-13942-POC-](https://github.com/shifa123/CVE-2020-13942-POC-)

### [CVE-2020-13942](CVE-2020-13942-lp008_CVE-2020-13942.md) 🔴

**名称:** CVE-2020-13942 Apache Unomi RCE
**类型:** 远程代码执行 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [CVE-2020-13942](https://github.com/lp008/CVE-2020-13942)

### [CVE-2020-13941](CVE-2020-13941-mbadanoiu_CVE-2020-13941.md) 🔴

**名称:** CVE-2020-13941: Apache Solr 绝对路径文件读取/写入漏洞
**类型:** 文件读取/写入 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [CVE-2020-13941](https://github.com/mbadanoiu/CVE-2020-13941)

### [CVE-2020-13777](CVE-2020-13777-0xxon_cve-2020-13777.md) 🔴

**名称:** CVE-2020-13777-GnuTLS会话票证漏洞
**类型:** 身份验证绕过/信息泄露 | **POC:** 是 | **投毒风险:** 5%
**仓库:** [cve-2020-13777](https://github.com/0xxon/cve-2020-13777)

### [CVE-2020-13777](CVE-2020-13777-prprhyt_PoC_TLS1_3_CVE-2020-13777.md) 🔴

**名称:** CVE-2020-13777-GnuTLS-会话票证加密漏洞
**类型:** TLS会话票证加密漏洞 | **POC:** 是 | **投毒风险:** 0%
**仓库:** [PoC_TLS1_3_CVE-2020-13777](https://github.com/prprhyt/PoC_TLS1_3_CVE-2020-13777)

### [CVE-2020-13777](CVE-2020-13777-shigeki_challenge_CVE-2020-13777.md) 🔴

**名称:** CVE-2020-13777 GnuTLS Session Ticket 漏洞
**类型:** 身份验证绕过/信息泄露 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [challenge_CVE-2020-13777](https://github.com/shigeki/challenge_CVE-2020-13777)

### [CVE-2020-13405](CVE-2020-13405-Moniruzzaman995_CVE-2020-13405.md)

**名称:** CVE-2020-13405-Microweber-用户信息泄露
**类型:** 信息泄露 | **POC:** 是 | **投毒风险:** 0%
**仓库:** [CVE-2020-13405](https://github.com/Moniruzzaman995/CVE-2020-13405)

### [CVE-2020-13405](CVE-2020-13405-mrnazu_CVE-2020-13405.md)

**名称:** CVE-2020-13405-Microweber-用户数据库泄露
**类型:** 信息泄露 | **POC:** 是 | **投毒风险:** 1%
**仓库:** [CVE-2020-13405](https://github.com/mrnazu/CVE-2020-13405)

### [CVE-2020-13398](CVE-2020-13398-SpiralBL0CK_PoC-crash-CVE-2020-13398-.md) 🔴

**名称:** CVE-2020-13398-FreeRDP-OOB写入
**类型:** OOB写入 | **POC:** 是 | **投毒风险:** 5%
**仓库:** [PoC-crash-CVE-2020-13398-](https://github.com/SpiralBL0CK/PoC-crash-CVE-2020-13398-)

### [CVE-2020-13151](CVE-2020-13151-ByteMe1001_CVE-2020-13151-POC-Aerospike-Server-Host-Command-Execution-RCE-.md) 🔴

**名称:** CVE-2020-13151-Aerospike-RCE
**类型:** 远程代码执行 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [CVE-2020-13151-POC-Aerospike-Server-Host-Command-Execution-RCE-](https://github.com/ByteMe1001/CVE-2020-13151-POC-Aerospike-Server-Host-Command-Execution-RCE-)

### [CVE-2020-13151](CVE-2020-13151-b4ny4n_CVE-2020-13151.md) 🔴

**名称:** CVE-2020-13151 - Aerospike UDF远程命令执行
**类型:** 远程命令执行 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [CVE-2020-13151](https://github.com/b4ny4n/CVE-2020-13151)

### [CVE-2020-11998](CVE-2020-11998-shoucheng3_apache__activemq_CVE-2020-11998_5-15-12.md) 🔴

**名称:** CVE-2020-11998 Apache ActiveMQ JMX RCE
**类型:** 远程代码执行 | **POC:** 否 | **投毒风险:** 0%
**仓库:** [apache__activemq_CVE-2020-11998_5-15-12](https://github.com/shoucheng3/apache__activemq_CVE-2020-11998_5-15-12)

### [CVE-2020-11989](CVE-2020-11989-cuijiung_shiro-CVE-2020-11989.md) 🔴

**名称:** CVE-2020-11989-Apache Shiro-身份验证绕过
**类型:** 身份验证绕过 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [shiro-CVE-2020-11989](https://github.com/cuijiung/shiro-CVE-2020-11989)

### [CVE-2020-11989](CVE-2020-11989-HYWZ36_HYWZ36-CVE-2020-11989-code.md) 🔴

**名称:** CVE-2020-11989-Apache Shiro Authentication Bypass
**类型:** Authentication Bypass | **POC:** 是 | **投毒风险:** 10%
**仓库:** [HYWZ36-CVE-2020-11989-code](https://github.com/HYWZ36/HYWZ36-CVE-2020-11989-code)

### [CVE-2020-11984](CVE-2020-11984-masahiro331_CVE-2020-11984.md) 🔴

**名称:** CVE-2020-11984-Apache HTTP Server-mod_proxy_uwsgi 缓冲区溢出
**类型:** 缓冲区溢出 | **POC:** 是 | **投毒风险:** 5%
**仓库:** [CVE-2020-11984](https://github.com/masahiro331/CVE-2020-11984)

### [CVE-2020-11978](CVE-2020-11978-pberba_CVE-2020-11978.md) 🔴

**名称:** CVE-2020-11978-Apache Airflow-远程代码执行
**类型:** 远程代码执行 (RCE) | **POC:** 是 | **投毒风险:** 0%
**仓库:** [CVE-2020-11978](https://github.com/pberba/CVE-2020-11978)

### [CVE-2020-11978](CVE-2020-11978-stuxbench_mlflow-cve-2020-11978.md) 🔴

**名称:** CVE-2020-11978-Apache Airflow-远程代码执行
**类型:** 远程代码执行 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [mlflow-cve-2020-11978](https://github.com/stuxbench/mlflow-cve-2020-11978)

### [CVE-2020-11651](CVE-2020-11651-Drew-Alleman_CVE-2020-11651.md) 🔴

**名称:** CVE-2020-11651 SaltStack 认证绕过/远程代码执行
**类型:** 认证绕过/远程代码执行 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [CVE-2020-11651](https://github.com/Drew-Alleman/CVE-2020-11651)

### [CVE-2020-11651](CVE-2020-11651-hardsoftsecurity_CVE-2020-11651-PoC.md) 🔴

**名称:** CVE-2020-11651-SaltStack-身份验证绕过和远程代码执行
**类型:** 身份验证绕过/远程代码执行 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [CVE-2020-11651-PoC](https://github.com/hardsoftsecurity/CVE-2020-11651-PoC)

### [CVE-2020-11651](CVE-2020-11651-ssrsec_CVE-2020-11651-CVE-2020-11652-EXP.md) 🔴

**名称:** CVE-2020-11651-SaltStack认证绕过与远程代码执行
**类型:** 认证绕过/远程代码执行 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [CVE-2020-11651-CVE-2020-11652-EXP](https://github.com/ssrsec/CVE-2020-11651-CVE-2020-11652-EXP)

### [CVE-2020-11651](CVE-2020-11651-chef-cft_salt-vulnerabilities.md) 🔴

**名称:** CVE-2020-11651-SaltStack-认证绕过
**类型:** 认证绕过 | **POC:** 是 | **投毒风险:** 5%
**仓库:** [salt-vulnerabilities](https://github.com/chef-cft/salt-vulnerabilities)

### [CVE-2020-11651](CVE-2020-11651-0xc0d_CVE-2020-11651.md) 🔴

**名称:** CVE-2020-11651-SaltStack-Authentication Bypass and Remote Code Execution
**类型:** Authentication Bypass and Remote Code Execution | **POC:** 是 | **投毒风险:** 10%
**仓库:** [CVE-2020-11651](https://github.com/0xc0d/CVE-2020-11651)

### [CVE-2020-11651](CVE-2020-11651-appcheck-ng_salt-rce-scanner-CVE-2020-11651-CVE-2020-11652.md)

**名称:** CVE-2020-11651 SaltStack 认证绕过及远程代码执行
**类型:** 认证绕过/远程代码执行 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [salt-rce-scanner-CVE-2020-11651-CVE-2020-11652](https://github.com/appcheck-ng/salt-rce-scanner-CVE-2020-11651-CVE-2020-11652)

### [CVE-2020-11651](CVE-2020-11651-jasperla_CVE-2020-11651-poc.md) 🔴

**名称:** CVE-2020-11651 - SaltStack 认证绕过漏洞
**类型:** 认证绕过 | **POC:** 是 | **投毒风险:** 1%
**仓库:** [CVE-2020-11651-poc](https://github.com/jasperla/CVE-2020-11651-poc)

### [CVE-2020-11651](CVE-2020-11651-rossengeorgiev_salt-security-backports.md) 🔴

**名称:** CVE-2020-11651 SaltStack 认证绕过和远程代码执行
**类型:** 认证绕过/远程代码执行 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [salt-security-backports](https://github.com/rossengeorgiev/salt-security-backports)

### [CVE-2020-11651](CVE-2020-11651-lovelyjuice_cve-2020-11651-exp-plus.md) 🔴

**名称:** CVE-2020-11651/CVE-2020-11652 SaltStack 身份验证绕过和任意文件读取/写入漏洞
**类型:** 身份验证绕过/任意文件读取/写入 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [cve-2020-11651-exp-plus](https://github.com/lovelyjuice/cve-2020-11651-exp-plus)

### [CVE-2020-11651](CVE-2020-11651-kevthehermit_CVE-2020-11651.md) 🔴

**名称:** CVE-2020-11651-SaltStack认证绕过与远程代码执行
**类型:** 认证绕过/远程代码执行 | **POC:** 是 | **投毒风险:** 5%
**仓库:** [CVE-2020-11651](https://github.com/kevthehermit/CVE-2020-11651)

### [CVE-2020-11651](CVE-2020-11651-RakhithJK_CVE-2020-11651.md) 🔴

**名称:** CVE-2020-11651-SaltStack-认证绕过和远程代码执行
**类型:** 认证绕过/远程代码执行 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [CVE-2020-11651](https://github.com/RakhithJK/CVE-2020-11651)

### [CVE-2020-11651](CVE-2020-11651-bravery9_SaltStack-Exp.md) 🔴

**名称:** CVE-2020-11651 SaltStack 认证绕过与远程代码执行
**类型:** 认证绕过/远程代码执行 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [SaltStack-Exp](https://github.com/bravery9/SaltStack-Exp)

### [CVE-2020-11651](CVE-2020-11651-dozernz_cve-2020-11651.md) 🔴

**名称:** CVE-2020-11651 SaltStack 身份验证绕过漏洞
**类型:** 身份验证绕过 | **POC:** 是 | **投毒风险:** 5%
**仓库:** [cve-2020-11651](https://github.com/dozernz/cve-2020-11651)

### [CVE-2020-11097](CVE-2020-11097-SpiralBL0CK_CVE-2020-11097-POC.md)

**名称:** CVE-2020-11097-FreeRDP-OOB读取
**类型:** OOB读取 | **POC:** 是 | **投毒风险:** 0%
**仓库:** [CVE-2020-11097-POC](https://github.com/SpiralBL0CK/CVE-2020-11097-POC)

### [CVE-2020-1054](CVE-2020-1054-Naman2701B_CVE-2020-1054.md) 🔴

**名称:** CVE-2020-1054 Win32k 权限提升漏洞
**类型:** 权限提升 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [CVE-2020-1054](https://github.com/Naman2701B/CVE-2020-1054)

### [CVE-2020-1054](CVE-2020-1054-Graham382_CVE-2020-1054.md) 🔴

**名称:** CVE-2020-1054 Win32k 权限提升漏洞
**类型:** 权限提升 | **POC:** 是 | **投毒风险:** 1%
**仓库:** [CVE-2020-1054](https://github.com/Graham382/CVE-2020-1054)

### [CVE-2020-1054](CVE-2020-1054-KaLendsi_CVE-2020-1054.md) 🔴

**名称:** CVE-2020-1054
**类型:** 权限提升 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [CVE-2020-1054](https://github.com/KaLendsi/CVE-2020-1054)

### [CVE-2020-1054](CVE-2020-1054-0xeb-bp_cve-2020-1054.md) 🔴

**名称:** CVE-2020-1054 Win32k 权限提升漏洞
**类型:** 权限提升 | **POC:** 是 | **投毒风险:** 1%
**仓库:** [cve-2020-1054](https://github.com/0xeb-bp/cve-2020-1054)

### [CVE-2020-1054](CVE-2020-1054-Iamgublin_CVE-2020-1054.md) 🔴

**名称:** CVE-2020-1054 - Win32k 权限提升漏洞
**类型:** 权限提升 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [CVE-2020-1054](https://github.com/Iamgublin/CVE-2020-1054)

### [CVE-2020-10199](CVE-2020-10199-finn79426_CVE-2020-10199.md) 🔴

**名称:** CVE-2020-10199-Sonatype Nexus Repository-JavaEL注入
**类型:** JavaEL注入 | **POC:** 是 | **投毒风险:** 1%
**仓库:** [CVE-2020-10199](https://github.com/finn79426/CVE-2020-10199)

### [CVE-2020-10199](CVE-2020-10199-hugosg97_CVE-2020-10199-Nexus-3.21.01.md) 🔴

**名称:** CVE-2020-10199-Sonatype Nexus Repository-JavaEL注入
**类型:** JavaEL注入 | **POC:** 是 | **投毒风险:** 0%
**仓库:** [CVE-2020-10199-Nexus-3.21.01](https://github.com/hugosg97/CVE-2020-10199-Nexus-3.21.01)

### [CVE-2020-10199](CVE-2020-10199-zhzyker_CVE-2020-10199_POC-EXP.md) 🔴

**名称:** CVE-2020-10199-Sonatype Nexus Repository-JavaEL注入
**类型:** JavaEL注入 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [CVE-2020-10199_POC-EXP](https://github.com/zhzyker/CVE-2020-10199_POC-EXP)

### [CVE-2020-10199](CVE-2020-10199-aleenzz_CVE-2020-10199.md) 🔴

**名称:** CVE-2020-10199-Sonatype Nexus Repository-JavaEL注入
**类型:** JavaEL注入 | **POC:** 是 | **投毒风险:** 0%
**仓库:** [CVE-2020-10199](https://github.com/aleenzz/CVE-2020-10199)

### [CVE-2020-10199](CVE-2020-10199-magicming200_CVE-2020-10199_CVE-2020-10204.md) 🔴

**名称:** CVE-2020-10199-Sonatype Nexus Repository-JavaEL注入
**类型:** JavaEL注入 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [CVE-2020-10199_CVE-2020-10204](https://github.com/magicming200/CVE-2020-10199_CVE-2020-10204)

### [CVE-2020-10199](CVE-2020-10199-jas502n_CVE-2020-10199.md) 🔴

**名称:** CVE-2020-10199-Sonatype Nexus Repository-JavaEL注入导致远程代码执行
**类型:** JavaEL注入 | **POC:** 是 | **投毒风险:** 0%
**仓库:** [CVE-2020-10199](https://github.com/jas502n/CVE-2020-10199)

### [CVE-2020-10199](CVE-2020-10199-wsfengfan_CVE-2020-10199-10204.md) 🔴

**名称:** CVE-2020-10199-Sonatype Nexus Repository-JavaEL Injection
**类型:** JavaEL Injection | **POC:** 是 | **投毒风险:** 0%
**仓库:** [CVE-2020-10199-10204](https://github.com/wsfengfan/CVE-2020-10199-10204)

### [CVE-2020-0796](CVE-2020-0796-madanokr001_CVE-2020-0796.md) 🔴

**名称:** CVE-2020-0796 SMBGhost 远程代码执行漏洞
**类型:** 远程代码执行 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [CVE-2020-0796](https://github.com/madanokr001/CVE-2020-0796)

### [CVE-2020-0796](CVE-2020-0796-monjheta_CVE-2020-0796.md) 🔴

**名称:** CVE-2020-0796-SMBGhost-远程代码执行
**类型:** 远程代码执行 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [CVE-2020-0796](https://github.com/monjheta/CVE-2020-0796)

### [CVE-2020-0796](CVE-2020-0796-Kaizzzo1_CVE-2020-0796.md) 🔴

**名称:** CVE-2020-0796-SMBGhost-远程代码执行
**类型:** 远程代码执行 | **POC:** 是 | **投毒风险:** 5%
**仓库:** [CVE-2020-0796](https://github.com/Kaizzzo1/CVE-2020-0796)

### [CVE-2020-0796](CVE-2020-0796-ran-sama_CVE-2020-0796.md) 🔴

**名称:** CVE-2020-0796 (SMBGhost)
**类型:** 远程代码执行 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [CVE-2020-0796](https://github.com/ran-sama/CVE-2020-0796)

### [CVE-2020-0796](CVE-2020-0796-z3ena_Exploiting-and-Mitigating-CVE-2020-0796-SMBGhost-and-Print-Spooler-Vulnerabilities.md) 🔴

**名称:** CVE-2020-0796-Windows SMBv3远程代码执行
**类型:** 远程代码执行 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [Exploiting-and-Mitigating-CVE-2020-0796-SMBGhost-and-Print-Spooler-Vulnerabilities](https://github.com/z3ena/Exploiting-and-Mitigating-CVE-2020-0796-SMBGhost-and-Print-Spooler-Vulnerabilities)

### [CVE-2020-0796](CVE-2020-0796-AdamSonov_smbGhostCVE-2020-0796.md) 🔴

**名称:** CVE-2020-0796-SMBGhost
**类型:** 远程代码执行 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [smbGhostCVE-2020-0796](https://github.com/AdamSonov/smbGhostCVE-2020-0796)

### [CVE-2020-0796](CVE-2020-0796-hungdnvp_POC-CVE-2020-0796.md)

**名称:** CVE-2020-0796 (SMBGhost)
**类型:** 远程代码执行 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [POC-CVE-2020-0796](https://github.com/hungdnvp/POC-CVE-2020-0796)

### [CVE-2020-0796](CVE-2020-0796-Opensitoo_cve-2020-0796.md) 🔴

**名称:** CVE-2020-0796-SMBGhost-远程代码执行
**类型:** 远程代码执行 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [cve-2020-0796](https://github.com/Opensitoo/cve-2020-0796)

### [CVE-2020-0796](CVE-2020-0796-OldDream666_cve-2020-0796.md) 🔴

**名称:** CVE-2020-0796 - SMBGhost 远程代码执行漏洞
**类型:** 远程代码执行 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [cve-2020-0796](https://github.com/OldDream666/cve-2020-0796)

### [CVE-2020-0796](CVE-2020-0796-dungnm24_CVE-2020-0796.md) 🔴

**名称:** CVE-2020-0796 SMBGhost RCE
**类型:** 远程代码执行 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [CVE-2020-0796](https://github.com/dungnm24/CVE-2020-0796)

### [CVE-2020-0796](CVE-2020-0796-w1ld3r_SMBGhost_Scanner.md) 🔴

**名称:** CVE-2020-0796 (SMBGhost)
**类型:** 远程代码执行 | **POC:** 是 | **投毒风险:** 1%
**仓库:** [SMBGhost_Scanner](https://github.com/w1ld3r/SMBGhost_Scanner)

### [CVE-2020-0796](CVE-2020-0796-T13nn3s_CVE-2020-0796.md) 🔴

**名称:** CVE-2020-0796 (SMBGhost)
**类型:** 远程代码执行 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [CVE-2020-0796](https://github.com/T13nn3s/CVE-2020-0796)

### [CVE-2020-0796](CVE-2020-0796-eerykitty_CVE-2020-0796-PoC.md) 🔴

**名称:** CVE-2020-0796 (SMBGhost)
**类型:** 远程代码执行 (RCE) | **POC:** 是 | **投毒风险:** 10%
**仓库:** [CVE-2020-0796-PoC](https://github.com/eerykitty/CVE-2020-0796-PoC)

### [CVE-2020-0796](CVE-2020-0796-krizzz07_CVE-2020-0796.md) 🔴

**名称:** CVE-2020-0796 (SMBGhost)
**类型:** 远程代码执行 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [CVE-2020-0796](https://github.com/krizzz07/CVE-2020-0796)

### [CVE-2020-0796](CVE-2020-0796-syadg123_CVE-2020-0796.md) 🔴

**名称:** CVE-2020-0796-SMBGhost-RCE
**类型:** 远程代码执行 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [CVE-2020-0796](https://github.com/syadg123/CVE-2020-0796)

### [CVE-2020-0796](CVE-2020-0796-SEHandler_CVE-2020-0796.md) 🔴

**名称:** CVE-2020-0796 SMBGhost 远程代码执行漏洞
**类型:** 远程代码执行 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [CVE-2020-0796](https://github.com/SEHandler/CVE-2020-0796)

### [CVE-2020-0796](CVE-2020-0796-awareseven_eternalghosttest.md) 🔴

**名称:** CVE-2020-0796 (SMBGhost)
**类型:** 远程代码执行 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [eternalghosttest](https://github.com/awareseven/eternalghosttest)

### [CVE-2020-0796](CVE-2020-0796-arzuozkan_CVE-2020-0796.md) 🔴

**名称:** CVE-2020-0796 SMBGhost 远程代码执行漏洞
**类型:** 远程代码执行 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [CVE-2020-0796](https://github.com/arzuozkan/CVE-2020-0796)

### [CVE-2020-0796](CVE-2020-0796-Barriuso_SMBGhost_AutomateExploitation.md) 🔴

**名称:** CVE-2020-0796-Windows SMBv3远程代码执行
**类型:** 远程代码执行 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [SMBGhost_AutomateExploitation](https://github.com/Barriuso/SMBGhost_AutomateExploitation)

### [CVE-2020-0796](CVE-2020-0796-vsai94_ECE9069_SMBGhost_Exploit_CVE-2020-0796-.md) 🔴

**名称:** CVE-2020-0796 (SMBGhost)
**类型:** 远程代码执行 (RCE) | **POC:** 是 | **投毒风险:** 10%
**仓库:** [ECE9069_SMBGhost_Exploit_CVE-2020-0796-](https://github.com/vsai94/ECE9069_SMBGhost_Exploit_CVE-2020-0796-)

### [CVE-2020-0796](CVE-2020-0796-julixsalas_CVE-2020-0796.md) 🔴

**名称:** CVE-2020-0796 - SMBGhost 远程代码执行漏洞
**类型:** 远程代码执行 | **POC:** 是 | **投毒风险:** 5%
**仓库:** [CVE-2020-0796](https://github.com/julixsalas/CVE-2020-0796)

### [CVE-2020-0796](CVE-2020-0796-lisinan988_CVE-2020-0796-exp.md) 🔴

**名称:** CVE-2020-0796 (SMBGhost) 远程代码执行漏洞
**类型:** 远程代码执行 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [CVE-2020-0796-exp](https://github.com/lisinan988/CVE-2020-0796-exp)

### [CVE-2020-0796](CVE-2020-0796-orangmuda_CVE-2020-0796.md) 🔴

**名称:** CVE-2020-0796 SMBGhost 远程代码执行漏洞
**类型:** 远程代码执行 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [CVE-2020-0796](https://github.com/orangmuda/CVE-2020-0796)

### [CVE-2020-0796](CVE-2020-0796-F6JO_CVE-2020-0796-Batch-scanning.md) 🔴

**名称:** CVE-2020-0796-SMBGhost
**类型:** 远程代码执行 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [CVE-2020-0796-Batch-scanning](https://github.com/F6JO/CVE-2020-0796-Batch-scanning)

### [CVE-2020-0796](CVE-2020-0796-Murasame-nc_CVE-2020-0796-LPE-POC.md) 🔴

**名称:** CVE-2020-0796 (SMBGhost) 本地提权漏洞
**类型:** 本地提权 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [CVE-2020-0796-LPE-POC](https://github.com/Murasame-nc/CVE-2020-0796-LPE-POC)

### [CVE-2020-0796](CVE-2020-0796-DannyRavi_nmap-scripts.md) 🔴

**名称:** CVE-2020-0796 (SMBGhost)
**类型:** 远程代码执行 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [nmap-scripts](https://github.com/DannyRavi/nmap-scripts)

### [CVE-2020-0796](CVE-2020-0796-tdevworks_CVE-2020-0796-SMBGhost-Exploit-Demo.md) 🔴

**名称:** CVE-2020-0796 (SMBGhost)
**类型:** 远程代码执行 (RCE) | **POC:** 是 | **投毒风险:** 10%
**仓库:** [CVE-2020-0796-SMBGhost-Exploit-Demo](https://github.com/tdevworks/CVE-2020-0796-SMBGhost-Exploit-Demo)

### [CVE-2020-0796](CVE-2020-0796-maqeel-git_CVE-2020-0796-SMBGhost.md) 🔴

**名称:** CVE-2020-0796 (SMBGhost)
**类型:** 远程代码执行 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [CVE-2020-0796-SMBGhost](https://github.com/maqeel-git/CVE-2020-0796-SMBGhost)

### [CVE-2020-0796](CVE-2020-0796-esmwaSpyware_DoS-PoC-for-CVE-2020-0796-SMBGhost-.md) 🔴

**名称:** CVE-2020-0796 - SMBGhost 远程代码执行漏洞
**类型:** 远程代码执行 | **POC:** 是 | **投毒风险:** 0%
**仓库:** [DoS-PoC-for-CVE-2020-0796-SMBGhost-](https://github.com/esmwaSpyware/DoS-PoC-for-CVE-2020-0796-SMBGhost-)

### [CVE-2020-0796](CVE-2020-0796-Jagadeesh7532_-CVE-2020-0796-SMBGhost-Windows-10-SMBv3-Remote-Code-Execution-Vulnerability.md) 🔴

**名称:** CVE-2020-0796 SMBGhost 远程代码执行漏洞
**类型:** 远程代码执行 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [-CVE-2020-0796-SMBGhost-Windows-10-SMBv3-Remote-Code-Execution-Vulnerability](https://github.com/Jagadeesh7532/-CVE-2020-0796-SMBGhost-Windows-10-SMBv3-Remote-Code-Execution-Vulnerability)

### [CVE-2020-0688](CVE-2020-0688-tvdat20004_CVE-2020-0688.md) 🔴

**名称:** CVE-2020-0688-Microsoft Exchange Server-RCE
**类型:** 远程代码执行 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [CVE-2020-0688](https://github.com/tvdat20004/CVE-2020-0688)

### [CVE-2020-0688](CVE-2020-0688-truongtn_cve-2020-0688.md) 🔴

**名称:** CVE-2020-0688 Microsoft Exchange Server 远程代码执行漏洞
**类型:** 远程代码执行 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [cve-2020-0688](https://github.com/truongtn/cve-2020-0688)

### [CVE-2020-0688](CVE-2020-0688-zyn3rgy_ecp_slap.md) 🔴

**名称:** CVE-2020-0688-Microsoft Exchange Server-远程代码执行
**类型:** 远程代码执行 | **POC:** 是 | **投毒风险:** 0%
**仓库:** [ecp_slap](https://github.com/zyn3rgy/ecp_slap)

### [CVE-2020-0688](CVE-2020-0688-W01fh4cker_CVE-2020-0688-GUI.md) 🔴

**名称:** CVE-2020-0688 Microsoft Exchange Server 远程代码执行漏洞
**类型:** 远程代码执行 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [CVE-2020-0688-GUI](https://github.com/W01fh4cker/CVE-2020-0688-GUI)

### [CVE-2020-0688](CVE-2020-0688-1337-llama_CVE-2020-0688-Python3.md) 🔴

**名称:** CVE-2020-0688 Microsoft Exchange Server 远程代码执行
**类型:** 远程代码执行 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [CVE-2020-0688-Python3](https://github.com/1337-llama/CVE-2020-0688-Python3)

### [CVE-2020-0688](CVE-2020-0688-w4fz5uck5_cve-2020-0688-webshell-upload-technique.md) 🔴

**名称:** CVE-2020-0688 Microsoft Exchange Server 远程代码执行漏洞
**类型:** 远程代码执行 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [cve-2020-0688-webshell-upload-technique](https://github.com/w4fz5uck5/cve-2020-0688-webshell-upload-technique)

### [CVE-2020-0688](CVE-2020-0688-chudamax_CVE-2020-0688-Exchange2010.md) 🔴

**名称:** CVE-2020-0688-Microsoft Exchange Server-远程代码执行
**类型:** 远程代码执行 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [CVE-2020-0688-Exchange2010](https://github.com/chudamax/CVE-2020-0688-Exchange2010)

### [CVE-2020-0688](CVE-2020-0688-Ridter_cve-2020-0688.md) 🔴

**名称:** CVE-2020-0688-Microsoft Exchange Server-远程代码执行
**类型:** 远程代码执行 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [cve-2020-0688](https://github.com/Ridter/cve-2020-0688)

### [CVE-2020-0688](CVE-2020-0688-7heKnight_CVE-2020-0688.md) 🔴

**名称:** CVE-2020-0688 Microsoft Exchange Server 远程代码执行漏洞
**类型:** 远程代码执行 (RCE) | **POC:** 是 | **投毒风险:** 10%
**仓库:** [CVE-2020-0688](https://github.com/7heKnight/CVE-2020-0688)

### [CVE-2020-0688](CVE-2020-0688-righter83_CVE-2020-0688.md) 🔴

**名称:** CVE-2020-0688
**类型:** 远程代码执行 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [CVE-2020-0688](https://github.com/righter83/CVE-2020-0688)

### [CVE-2020-0688](CVE-2020-0688-MrTiz_CVE-2020-0688.md) 🔴

**名称:** CVE-2020-0688-Microsoft Exchange Server-远程代码执行
**类型:** 远程代码执行 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [CVE-2020-0688](https://github.com/MrTiz/CVE-2020-0688)

### [CVE-2020-0688](CVE-2020-0688-onSec-fr_CVE-2020-0688-Scanner.md) 🔴

**名称:** CVE-2020-0688-Microsoft Exchange Server-远程代码执行
**类型:** 远程代码执行 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [CVE-2020-0688-Scanner](https://github.com/onSec-fr/CVE-2020-0688-Scanner)

### [CVE-2020-0688](CVE-2020-0688-SLSteff_CVE-2020-0688-Scanner.md) 🔴

**名称:** CVE-2020-0688-Microsoft Exchange-远程代码执行
**类型:** 远程代码执行 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [CVE-2020-0688-Scanner](https://github.com/SLSteff/CVE-2020-0688-Scanner)

### [CVE-2020-0688](CVE-2020-0688-murataydemir_CVE-2020-0688.md) 🔴

**名称:** CVE-2020-0688 Microsoft Exchange Server 远程代码执行漏洞
**类型:** 远程代码执行 (RCE) | **POC:** 是 | **投毒风险:** 0%
**仓库:** [CVE-2020-0688](https://github.com/murataydemir/CVE-2020-0688)

### [CVE-2020-0688](CVE-2020-0688-ktpdpro_CVE-2020-0688.md) 🔴

**名称:** CVE-2020-0688 Microsoft Exchange Server 远程代码执行
**类型:** 远程代码执行 (RCE) | **POC:** 是 | **投毒风险:** 10%
**仓库:** [CVE-2020-0688](https://github.com/ktpdpro/CVE-2020-0688)

### [CVE-2020-0688](CVE-2020-0688-ravinacademy_CVE-2020-0688.md) 🔴

**名称:** CVE-2020-0688 Microsoft Exchange Server 远程代码执行漏洞
**类型:** 远程代码执行 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [CVE-2020-0688](https://github.com/ravinacademy/CVE-2020-0688)

### [CVE-2020-0688](CVE-2020-0688-zcgonvh_CVE-2020-0688.md) 🔴

**名称:** CVE-2020-0688 Microsoft Exchange Server Remote Code Execution
**类型:** 远程代码执行 | **POC:** 是 | **投毒风险:** 1%
**仓库:** [CVE-2020-0688](https://github.com/zcgonvh/CVE-2020-0688)

### [CVE-2020-0688](CVE-2020-0688-justin-p_PSForgot2kEyXCHANGE.md) 🔴

**名称:** CVE-2020-0688 Microsoft Exchange Server 远程代码执行漏洞
**类型:** 远程代码执行 (RCE) | **POC:** 是 | **投毒风险:** 10%
**仓库:** [PSForgot2kEyXCHANGE](https://github.com/justin-p/PSForgot2kEyXCHANGE)

### [CVE-2020-0688](CVE-2020-0688-youncyb_CVE-2020-0688.md) 🔴

**名称:** CVE-2020-0688 Microsoft Exchange Server 远程代码执行漏洞
**类型:** 远程代码执行 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [CVE-2020-0688](https://github.com/youncyb/CVE-2020-0688)

### [CVE-2020-0688](CVE-2020-0688-Yt1g3r_CVE-2020-0688_EXP.md) 🔴

**名称:** CVE-2020-0688 - Microsoft Exchange Server 远程代码执行
**类型:** 远程代码执行 (RCE) | **POC:** 是 | **投毒风险:** 10%
**仓库:** [CVE-2020-0688_EXP](https://github.com/Yt1g3r/CVE-2020-0688_EXP)

### [CVE-2020-0688](CVE-2020-0688-Jumbo-WJB_CVE-2020-0688.md) 🔴

**名称:** CVE-2020-0688 Microsoft Exchange Server 远程代码执行
**类型:** 远程代码执行 | **POC:** 是 | **投毒风险:** 5%
**仓库:** [CVE-2020-0688](https://github.com/Jumbo-WJB/CVE-2020-0688)

### [CVE-2020-0688](CVE-2020-0688-mahyarx_Exploit_CVE-2020-0688.md) 🔴

**名称:** CVE-2020-0688-Microsoft Exchange Server-远程代码执行
**类型:** 远程代码执行 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [Exploit_CVE-2020-0688](https://github.com/mahyarx/Exploit_CVE-2020-0688)

### [CVE-2020-0688](CVE-2020-0688-cert-lv_CVE-2020-0688.md) 🔴

**名称:** CVE-2020-0688 Microsoft Exchange Server 远程代码执行漏洞
**类型:** 远程代码执行 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [CVE-2020-0688](https://github.com/cert-lv/CVE-2020-0688)

### [CVE-2020-0688](CVE-2020-0688-random-robbie_cve-2020-0688.md) 🔴

**名称:** CVE-2020-0688-Microsoft Exchange Server-远程代码执行
**类型:** 远程代码执行 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [cve-2020-0688](https://github.com/random-robbie/cve-2020-0688)

### [CVE-2020-0665](CVE-2020-0665-gunzf0x_CVE-2020-0665.md) 🔴

**名称:** CVE-2020-0665 Active Directory 权限提升
**类型:** 权限提升 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [CVE-2020-0665](https://github.com/gunzf0x/CVE-2020-0665)

### [CVE-2020-0618](CVE-2020-0618-N3xtGenH4cker_CVE-2020-0618_DETECTION.md) 🔴

**名称:** CVE-2020-0618 - Microsoft SQL Server Reporting Services (SSRS) 远程代码执行漏洞
**类型:** 远程代码执行 | **POC:** 是 | **投毒风险:** 0%
**仓库:** [CVE-2020-0618_DETECTION](https://github.com/N3xtGenH4cker/CVE-2020-0618_DETECTION)

### [CVE-2020-0618](CVE-2020-0618-itstarsec_CVE-2020-0618.md) 🔴

**名称:** CVE-2020-0618 - Microsoft SQL Server Reporting Services RCE
**类型:** 远程代码执行 (RCE) | **POC:** 是 | **投毒风险:** 10%
**仓库:** [CVE-2020-0618](https://github.com/itstarsec/CVE-2020-0618)

### [CVE-2020-0618](CVE-2020-0618-wortell_cve-2020-0618.md) 🔴

**名称:** CVE-2020-0618 Microsoft SQL Server Reporting Services RCE Honeypot
**类型:** 远程代码执行 (RCE) | **POC:** 是 | **投毒风险:** 5%
**仓库:** [cve-2020-0618](https://github.com/wortell/cve-2020-0618)

### [CVE-2020-0618](CVE-2020-0618-euphrat1ca_CVE-2020-0618.md) 🔴

**名称:** CVE-2020-0618 - Microsoft SQL Server Reporting Services Remote Code Execution
**类型:** 远程代码执行 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [CVE-2020-0618](https://github.com/euphrat1ca/CVE-2020-0618)

### [CVE-2020-0610](CVE-2020-0610-ImBIOS_lab-cve-2020-0610.md) 🔴

**名称:** CVE-2020-0610 Windows Remote Desktop Gateway (RD Gateway) 远程代码执行漏洞
**类型:** 远程代码执行 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [lab-cve-2020-0610](https://github.com/ImBIOS/lab-cve-2020-0610)

### [CVE-2020-0610](CVE-2020-0610-Riocipta75_lab-cve-2020-0610.md) 🔴

**名称:** CVE-2020-0610 Windows Remote Desktop Gateway (RD Gateway) 远程代码执行漏洞
**类型:** 远程代码执行 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [lab-cve-2020-0610](https://github.com/Riocipta75/lab-cve-2020-0610)

### [CVE-2020-0423](CVE-2020-0423-sparrow-labz_CVE-2020-0423.md) 🔴

**名称:** CVE-2020-0423-Android-Binder-UAF
**类型:** Use-After-Free | **POC:** 是 | **投毒风险:** 0%
**仓库:** [CVE-2020-0423](https://github.com/sparrow-labz/CVE-2020-0423)

### [CVE-2020-0192](CVE-2020-0192-himanshu67111_CVE-2020-0192.md)

**名称:** CVE-2020-0192
**类型:** 信息泄露 | **POC:** 是 | **投毒风险:** 10%
**仓库:** [CVE-2020-0192](https://github.com/himanshu67111/CVE-2020-0192)


---

## 📖 说明

- 🔴 标记为高危漏洞
- ⚠️ 标记为高投毒风险（≥70%）
- 漏洞按CVE编号降序排列
- 点击CVE编号查看详细分析报告

