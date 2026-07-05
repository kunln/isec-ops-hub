# TDP 日志查询指令说明

> 来源：<TDP domain>/investigation/logquerys/instruction

## 操作符说明

| 操作符 | 运算逻辑 | 说明 | 查询示例 |
| --- | --- | --- | --- |
| AND | 与运算 | 两个及以上筛选项之间的运算，取交集 | threat.level = 'attack' AND direction = 'in' |
| OR | 或运算 | 两个及以上筛选项之间的运算，取并集 | threat.name = '海莲花团伙' OR threat.level = 'attack' AND direction = 'in' |
| = | 等于 | 查询单个值，适用于  1.筛选条件为固定值的，比如威胁类型、行为类型、严重级别等等  2.精确查询条件为输入值的，比如攻击者IP、威胁名称、URL或域名等等 | threat.level = 'attack' |
| > | 大于 | 适用于查询筛选条件为数值的，比如HTTP请求长度、发送流量等等，筛选数值时不要加单引号 | net.bytes\_toserver > 1000 |
| >= | 大于等于 | 适用于查询筛选条件为数值的，比如HTTP请求长度、发送流量等等，筛选数值时不要加单引号 | net.bytes\_toserver >= 1000 |
| < | 小于 | 适用于查询筛选条件为数值的，比如HTTP请求长度、发送流量等等，筛选数值时不要加单引号 | net.bytes\_toserver < 1000 |
| <= | 小于等于 | 适用于查询筛选条件为数值的，比如HTTP请求长度、发送流量等等，筛选数值时不要加单引号 | net.bytes\_toserver <= 1000 |
| <> | 不等于 | 排除单个值，适用于  1.筛选条件为固定值的，比如威胁类型、行为类型、严重级别等等  2.精确查询条件为输入值的，比如攻击者IP、威胁名称、URL或域名等等 | net.bytes\_toserver <> 1000 |
| is | 字段值不存在 | 查询字段值不存在情况，比如严重级别为空 | threat.level is null |
| is not | 排除字段值不存在 | 排除查询字段值不存在的情况，比如严重级别不为空 | threat.level is not null |
| LIKE | 模糊匹配值 | 模糊查询的输入值，以查询IP地址为例： 1.查询所有IP地址中包含“10.10”，输入格式为'%10.10%' 2.查询所有以“10.10”开头的IP地址，输入格式为'10.10%' 3.查询所有以“10.10”结尾的IP地址，输入格式为'%10.10' | net.dest\_ip like '%10.10%'  net.dest\_ip like '10.10%'  net.dest\_ip like '%10.10' |
| NOT LIKE | 排除模糊匹配值 | 排除模糊查询的输入值，以查询IP地址为例： 1.排除查询所有IP地址中包含“10.10”，输入格式为'%10.10%' 2.排除查询所有以“10.10”开头的IP地址，输入格式为'10.10%' 3.排除查询所有以“10.10”结尾的IP地址，输入格式为'%10.10' | net.dest\_ip not like '%10.10%'  net.dest\_ip not like '10.10%'  net.dest\_ip not like '%10.10' |
| IN | 包含多个值 | 查询多个值，适用于  1.筛选条件为固定值的，比如威胁类型、行为类型、严重级别等等  2.精确查询条件为输入值的，比如攻击者IP、威胁名称、URL或域名等等 | attacker IN ('12.34.56.78', '34.23.56.78')  筛选多个条件时需要加括号 |
| NOT IN | 不包含多个值 | 排除多个值，适用于  1.筛选条件为固定值的，比如威胁类型、行为类型、严重级别等等  2.精确查询条件为输入值的，比如攻击者IP、威胁名称、URL或域名等等 | attacker NOT IN ('12.34.56.78', '34.23.56.78')  排除多个条件时需要加括号 |

## 字段说明

| 字段 | 字段名称 | 字段类型 | 说明 | 查询示例 |
| --- | --- | --- | --- | --- |
| threat.level | 行为类型 | enum | attack-攻击  action-敏感行为  risk-风险  null-网络连接 | threat.level = 'action' |
| threat.result | 攻击结果 | enum | success-成功  failed-失败  unknown-尝试 | threat.result <> 'unknown' |
| packet\_direction | 流量方向 | enum | lateral-内 -> 内  out-内 -> 外  in-外 -> 内 | packet\_direction= 'in' |
| net.src\_ip | 源IP | string | 输入值 | net.src\_ip NOT IN ('12.34.56.78', '34.23.56.78') |
| net.dest\_ip | 目的IP | string | 输入值 | net.dest\_ip NOT IN ('12.34.56.78', '34.23.56.78') |
| attacker | 攻击者IP | string | 输入值 | attacker NOT IN ('12.34.56.78', '34.23.56.78') |
| victim | 受害者IP | string | 输入值 | victim IN ('12.34.56.78', '34.23.56.78') |
| machine | 告警主机IP | string | 输入值 | machine IN ('12.34.56.78', '34.23.56.78') |
| data | URL或域名 | string | 输入值 | data LIKE '%com%' |
| direction | 威胁方向 | enum | in-外部攻击和投递  out-失陷破坏  lateral-内网渗透 | direction = 'in' |
| threat.type | 威胁类型 | enum | recon-侦查  exploit-漏洞利用  shell-网站后门&Shell  c2-连接远控地址  trojan-木马 [+21] | threat.type NOT IN ('trojan','exploit','shell') |
| threat.severity | 严重级别 | enum | 0-信息  1-低  2-中  3-高  4-严重 | threat.severity IN ('1','2') |
| threat.phase | 攻击阶段 | enum | recon-侦查  exploit-漏洞利用  control-控制  attack\_out-对外攻击  post\_exploit-内网渗透 | threat.phase = 'exploit' |
| threat.name | 威胁名称 | string | 输入值 | threat.name LIKE '%漏洞利用%' |
| dest\_assets.name | 目的资产名称 | string | 输入值 | dest\_assets.name = '张三的电脑' |
| dest\_assets.section | 目的资产类型 | enum | 终端-终端  服务器-服务器 | dest\_assets.section = '终端' |
| dest\_assets.sub\_type | 目的资产子类型 | enum | loadbalance-反向代理  dns-DNS  bastionhost-堡垒机  proxy-代理  ad-AD域控 [+2] | dest\_assets.sub\_type = 'loadbalance' |
| net.dest\_port | 目的端口 | int | 输入值 | net.dest\_port IN ('44','55') |
| net.src\_port | 源端口 | int | 输入值 | net.src\_port IN ('44','55') |
| is\_hw\_ip | HW IP相关行为 | bool | 1-是  0-否 | is\_hw\_ip = '1' |
| hw\_ip\_level | HW攻击IP可信度 | enum | 1-高可信  2-已确认 | hw\_ip\_level = '2' |
| hw\_ip\_report | HW溯源报告 | bool | 1-是  0-否 | hw\_ip\_report = '0' |
| ip\_reputation | IP信誉 | enum | c2-远控  botnet-僵尸网络  hijacked-劫持  phishing-钓鱼  malware-恶意软件 [+59] | ip\_reputation IN ('malware','suspicious\_coinminer') |
| threat.is\_connected | 是否连通 | bool | 1-是  0-否 | threat.is\_connected= '0' |
| threat.is\_apt | 是否APT | bool | 1-是  0-否 | threat.is\_apt= '0' |
| is\_newfile | 新增文件 | bool | 1-是  0-否 | is\_newfile= '0' |
| threat.suuid | 情报/规则/模型ID | string | 输入值 | threat.suuid = 'S9850109444' |
| external\_ip | 对端IP | string | 输入值 | external\_ip NOT IN ('12.34.56.78', '34.23.56.78') |
| threat.module | 检测模块 | string | 输入值 | threat.module = 'file' |
| threat.msg | 威胁信息 | string | 输入值 | threat.msg LIKE '%用户名%' |
| incident\_id | 威胁事件ID | string | 输入值 | incident\_id in ('ebc8d286b73f4c617808f32850dcb75c-1653997925') |
| flow\_id | 流ID | string | 输入值 | flow\_id = '2145350174711699' |
| id | 日志文档ID | string | 输入值 | id = 'tKsuvZwB9xnfdEa7FmgL' |
| threat.tag | 威胁标签 | string | 输入值 | threat.tag like '%爆破%' |
| is\_black\_ip | 是否黑IP访问 | bool | 1-是  0-否 | is\_black\_ip= '0' |
| threat.characters | 威胁性质 | enum | is\_compromised-已失陷  is\_connected-建立远控连接  is\_apt-APT  is\_lateral-发起内网渗透  is\_in\_success-被外部攻击成功 [+4] | threat.characters = 'is\_compromised' |
| net.proto | 传输层协议 | enum | TCP-TCP  UDP-UDP  ICMP-ICMP | net.proto = 'TCP' |
| net.protocol\_version | 协议版本 | enum | http2-HTTP2 | net.protocol\_version = 'http2' |
| net.app\_proto | 应用层协议 | enum | ajp-AJP  CouchDB-CouchDB  DB2-DB2  DCERPC-DCERPC  dns-DNS [+57] | net.app\_proto IN ('t3','ldap','smb') |
| net.is\_ipv6 | 是否为IPv6 | bool | 1-是  0-否 | net.is\_ipv6 = '0' |
| net.type | 协议类型 | enum | TCP-TCP  UDP-UDP  ICMP-ICMP  ajp-AJP  CouchDB-CouchDB [+60] | net.type IN ('t3','ldap'.'smb') |
| net.bytes\_toserver | 发送流量 | int | 输入值 | net.bytes\_toserver > 1000 |
| net.bytes\_toclient | 接收流量 | int | 输入值 | net.bytes\_toclient <= 2000 |
| net.real\_src\_ip | 真实源IP | string | 输入值 | net.real\_src\_ip = '12.34.56.78' |
| net.http\_xff | HTTP XFF | string | 输入值 | net.http\_xff = '102.20.56.78' |
| net.http.method | HTTP方法 | enum | GET-GET  POST-POST  HEAD-HEAD  PUT-PUT  DELETE-DELETE | net.http.method = 'POST' |
| net.http.status | HTTP返回码 | string | 输入值 | net.http.status = '200' |
| net.http.reqs\_header | HTTP请求头 | string | 输入值 | net.http.reqs\_header LIKE '%token%' |
| net.http.reqs\_host | HTTP主机 | string | 输入值 | net.http.reqs\_host = '192.168.100.55:8888' |
| net.http.reqs\_cookie | HTTP Cookie | string | 输入值 | net.http.reqs\_cookie = 'token=1e9c07e135a15e40b3290c320245ca9a' |
| net.http.reqs\_body | HTTP请求体 | string | 输入值 | net.http.reqs\_body is not null |
| net.http.reqs\_line | HTTP请求行 | string | 输入值 | net.http.reqs\_line = 'POST /login.php HTTP/1.1' |
| net.http.reqs\_referer | HTTP Refer | string | 输入值 | net.http.reqs\_referer is null |
| net.http.url | HTTP URL | string | 输入值 | net.http.url LIKE '%login.php%' |
| net.http.reqs\_user\_agent | HTTP UA | string | 输入值 | net.http.reqs\_user\_agent is not null |
| net.http.resp\_header | HTTP响应头 | string | 输入值 | net.http.resp\_header LIKE '%token%' |
| net.http.resp\_line | HTTP响应行 | string | 输入值 | net.http.resp\_line = 'HTTP/1.0 200 OK' |
| net.http.resp\_body | HTTP响应体 | string | 输入值 | net.http.resp\_body is not null |
| net.http.reqs\_content\_length | HTTP请求长度 | int | 输入值 | net.http.reqs\_content\_length < 2000 |
| net.http.resp\_content\_length | HTTP返回长度 | int | 输入值 | net.http.resp\_content\_length > 2000 |
| net.dns.type | DNS方向 | enum | query-请求(query)  answer-应答(answer) | net.dns.type = 'query' |
| net.dns.rrname | DNS请求域名 | string | 输入值 | net.dns.rrname = 'us-u.openx.net' |
| net.dns.rrtype | DNS请求类型 | enum | A-A  AAAA-AAAA  TXT-TXT  CNAME-CNAME  SRV-SRV [+3] | net.dns.rrtype IN ('TXT','SOA') |
| net.dns.rdata | DNS返回结果 | string | 输入值 | net.dns.rdata <> 'cs9.wac.phicdn.net' |
| url\_pattern | 修正的URL | string | 输入值 | url\_pattern LIKE '%com%' |
| geo\_data.Country | 国家和地区 | string | 输入值 | geo\_data.Country IN ('美国','英国') |
| geo\_data.Province | 省 | string | 输入值 | geo\_data.Province IN ('辽宁省') |
| geo\_data.City | 市 | string | 输入值 | geo\_data.City IN ('北京市') |
| input\_syslog\_type | 接入日志的类型 | enum | Hfish-蜜罐日志  dns-DNS日志  http-HTTP/HTTPS日志  vpn\_success-VPN登录成功日志  vpn\_failed-VPN登录失败日志 [+1] | input\_syslog\_type = 'Hfish' |
| net.s2c\_vlan | 包含从服务端至客户端方向的VLAN ID | int | 输入值 | net.s2c\_vlan IN ('2104') |
| threat.is\_0day | 0day攻击 | bool | 1-是  0-否 | threat.is\_0day= '0' |
| threat.id | 告警ID | string | 输入值 | threat.id= 'ceqfd0ua14mci4l49k90' |
| dest\_assets.is\_target | 目的资产是否靶标 | bool | 1-是  0-否 | --- |
| assets.level | 资产级别 | enum | 1-普通  2-重要 | assets.level= '1' |
| threat.detect\_source | 告警来源 | enum | onesig-onesig | threat.detect\_source= 'onesig' |
| assets.contact\_details | 联系方式 | string | 输入值 | --- |
| assets.department | 管理部门 | string | 输入值 | --- |
| assets.group\_name | 业务组名称 | string | 输入值 | --- |
| assets.host\_os | 操作系统 | string | 输入值 | --- |
| assets.ip | 资产IP | string | 输入值 | --- |
| assets.is\_target | 是否靶标 | bool | 1-是  0-否 | assets.is\_target= '0' |
| assets.mac | MAC地址 | string | 输入值 | --- |
| assets.name | 资产名称 | string | 输入值 | assets.name = '张三的电脑' |
| assets.remark | 资产备注 | string | 输入值 | --- |
| assets.responsible\_person | 资产负责人 | string | 输入值 | --- |
| assets.section | 资产类型 | enum | 终端-终端  服务器-服务器 | assets.section = '终端' |
| assets.source | 资产来源 | string | 输入值 | --- |
| assets.sub\_type | 资产子类型 | enum | loadbalance-反向代理  dns-DNS  bastionhost-堡垒机  proxy-代理  ad-AD域控 [+2] | assets.sub\_type = 'loadbalance' |
| assets.zone | 部署位置 | string | 输入值 | --- |
| dest\_assets.contact\_details | 目的资产联系方式 | string | 输入值 | --- |
| dest\_assets.department | 目的资产管理部门 | string | 输入值 | --- |
| dest\_assets.group\_name | 目的资产业务组名称 | string | 输入值 | --- |
| dest\_assets.host\_os | 目的资产操作系统 | string | 输入值 | --- |
| dest\_assets.ip | 目的资产IP | string | 输入值 | --- |
| dest\_assets.level | 目的资产级别 | enum | 1-普通  2-重要 | dest\_assets.level= '1' |
| dest\_assets.mac | 目的资产MAC地址 | string | 输入值 | --- |
| dest\_assets.remark | 目的资产备注 | string | 输入值 | --- |
| dest\_assets.responsible\_person | 目的资产负责人 | string | 输入值 | --- |
| dest\_assets.source | 目的资产来源 | string | 输入值 | --- |
| dest\_assets.zone | 目的资产部署位置 | string | 输入值 | --- |
| device\_id | 设备ID | string | 输入值 | --- |
| external\_port | 对端端口 | int | 输入值 | --- |
| hash | 文件HASH | string | 输入值 | --- |
| net.c2s\_vlan | 包含从客户端至服务端方向的VLAN ID | int | 输入值 | net.c2s\_vlan IN ('2104') |
| net.ftp.pass | FTP 密码 | string | 输入值 | --- |
| net.ftp.status | FTP 状态 | string | 输入值 | --- |
| net.ftp.type | FTP 类型 | string | 输入值 | --- |
| net.ftp.user | FTP 用户名 | string | 输入值 | --- |
| net.imap.type | IMAP 行为类型 | string | 输入值 | --- |
| net.imap.user | IMAP 用户名 | string | 输入值 | --- |
| net.imap.pass | IMAP 密码 | string | 输入值 | --- |
| net.imap.email.status | IMAP 邮件状态 | string | 输入值 | --- |
| net.imap.email.from | IMAP 发件人 | string | 输入值 | --- |
| net.imap.email.to | IMAP 收件人 | string | 输入值 | --- |
| net.imap.email.subject | IMAP 邮件主题 | string | 输入值 | net.imap.email.subject LIKE '%Testing%' |
| net.imap.email.headers | IMAP 邮件头 | string | 输入值 | --- |
| net.imap.email.body\_text | IMAP 邮件正文 | string | 输入值 | --- |
| net.imap.email.attachment.filename | IMAP 邮件附件 | string | 输入值 | --- |
| net.is\_https | 解密流量 | bool | 1-是  0-否 | --- |
| net.krb5.addresses | Kerberos5 地址 | string | 输入值 | --- |
| net.krb5.cname | Kerberos5 客户用户名 | string | 输入值 | --- |
| net.krb5.sname | Kerberos5 域服务器名 | string | 输入值 | --- |
| net.ldap.pass | LDAP 密码 | string | 输入值 | --- |
| net.ldap.status | LDAP 状态 | string | 输入值 | --- |
| net.ldap.type | LDAP 行为类型 | string | 输入值 | --- |
| net.ldap.user | LDAP 用户名 | string | 输入值 | --- |
| net.mysql.database | MYSQL 数据库 | string | 输入值 | --- |
| net.mysql.pass | MYSQL 密码 | string | 输入值 | --- |
| net.mysql.status | MYSQL 状态 | string | 输入值 | --- |
| net.mysql.type | MYSQL 行为类型 | string | 输入值 | --- |
| net.mysql.user | MYSQL 用户名 | string | 输入值 | --- |
| net.pkts\_toclient | 接收包数 | int | 输入值 | --- |
| net.pkts\_toserver | 发送包数 | int | 输入值 | --- |
| net.pop3.type | POP3 行为类型 | string | 输入值 | --- |
| net.pop3.pass | POP3 密码 | string | 输入值 | --- |
| net.pop3.user | POP3 用户名 | string | 输入值 | --- |
| net.pop3.auth\_mechanism | POP3鉴权方式 | string | 输入值 | --- |
| net.pop3.email.from | POP3 发件人 | string | 输入值 | --- |
| net.pop3.email.to | POP3 收件人 | string | 输入值 | --- |
| net.pop3.email.subject | POP3 邮件主题 | string | 输入值 | net.pop3.email.subject LIKE '%Testing%' |
| net.pop3.email.status | POP3 邮件状态 | string | 输入值 | --- |
| net.pop3.email.headers | POP3 邮件头 | string | 输入值 | --- |
| net.pop3.email.body\_text | POP3 邮件正文 | string | 输入值 | --- |
| net.pop3.email.attachment.filename | POP3 邮件附件 | string | 输入值 | --- |
| net.postgresql.pass | POSTGRESQL 密码 | string | 输入值 | --- |
| net.postgresql.status | POSTGRESQL 状态 | string | 输入值 | --- |
| net.postgresql.type | POSTGRESQL 行为类型 | string | 输入值 | --- |
| net.postgresql.user | POSTGRESQL 用户名 | string | 输入值 | --- |
| net.redis.pass | REDIS 密码 | string | 输入值 | --- |
| net.redis.status | REDIS 状态 | string | 输入值 | --- |
| net.redis.type | REDIS 行为类型 | string | 输入值 | --- |
| net.smb.type | SMB 行为类型 | string | 输入值 | --- |
| net.smb.status | SMB 状态 | string | 输入值 | --- |
| net.smtp.type | SMTP 行为类型 | string | 输入值 | --- |
| net.smtp.user | SMTP 用户名 | string | 输入值 | --- |
| net.smtp.pass | SMTP 密码 | string | 输入值 | --- |
| net.smtp.auth\_mechanism | SMTP 鉴权方式 | string | 输入值 | --- |
| net.smtp.email.from | SMTP 发件人 | string | 输入值 | --- |
| net.smtp.email.to | SMTP 收件人 | string | 输入值 | --- |
| net.smtp.email.subject | SMTP 邮件主题 | string | 输入值 | net.smtp.email.subject LIKE '%Testing%' |
| net.smtp.email.status | SMTP 邮件状态 | string | 输入值 | --- |
| net.smtp.email.headers | SMTP 邮件头 | string | 输入值 | --- |
| net.smtp.email.body\_text | SMTP 邮件正文 | string | 输入值 | --- |
| net.smtp.email.attachment.filename | SMTP 邮件附件 | string | 输入值 | --- |
| net.telnet.pass | TELNET 密码 | string | 输入值 | --- |
| net.telnet.status | TELNET 状态 | string | 输入值 | --- |
| net.telnet.type | TELNET 行为类型 | string | 输入值 | --- |
| net.telnet.user | TELNET 用户名 | string | 输入值 | --- |
| net.tls.version | TLS 版本 | string | 输入值 | --- |
| net.tls.key\_ex | 密钥交换算法 | enum | RSA-RSA  ECDHE-ECDHE  OTHER-其他 | --- |
| net.tcp\_option\_ip | TCP Option IP | string | 输入值 | --- |
| net.tcp\_option\_port | TCP Option Port | int | 输入值 | --- |
| pcap\_sha256 | PCAP HASH | string | 输入值 | --- |
| raw\_data | 原始数据 | string | 输入值 | --- |
| threat.custom\_adjustment | 是否经过自定义告警调整 | bool | 1-是  0-否 | --- |
| threat.ioc | 威胁情报 | string | 输入值 | --- |
| threat.is\_custom | 是否为自定义规则检出 | bool | 1-是  0-否 | --- |
| threat.is\_risk\_policy | 是否为自定义风险策略检出 | bool | 1-是  0-否 | --- |
| time | 时间 | int | 输入值 | --- |
| threat.tactics\_id | ATT&CK ID | enum | T1055.011-T1055.011  T1053.005-T1053.005  T1205.002-T1205.002  T1066-T1066  T1560.001-T1560.001 [+794] | threat.tactics\_id = 'T1596.002' |
| threat.tactics | ATT&CK | enum | Extra Window Memory Injection-Extra Window Memory Injection  Scheduled Task-Scheduled Task  Socket Filters-Socket Filters  Indicator Removal from Tools-Indicator Removal from Tools  Archive via Utility-Archive via Utility [+666] | threat.tactics = 'WHOIS' |
| threat.alert\_policy\_name | 自定义告警策略名称 | string | 输入值 | --- |
| assets.tag | 资产标签 | enum | 123123-123123  aaaaaaaaa-aaaaaaaaa  测试-测试  DNS-DNS  扫描器-扫描器 [+4] | assets.tag = 'tag\_one' |
| dest\_assets.tag | 目的资产标签 | enum | 123123-123123  aaaaaaaaa-aaaaaaaaa  测试-测试  DNS-DNS  扫描器-扫描器 [+4] | dest\_assets.tag = 'tag\_one' |
| intercept\_by\_onedns | 是否已被DNS拦截 | bool | 1-是  0-否 | intercept\_by\_onedns= '0' |


*文档版本：TDP 3.3.9*  
*更新时间：2026-02-06*  