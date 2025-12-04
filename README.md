**这段脚本是一个基于 Python 多进程的自动化端口扫描与资产分析工具，采用了“漏斗式”的处理逻辑，旨在平衡扫描速度与信息深度。具体逻辑分析如下**：

**分级扫描架构**：

**第一级（快速探测）**：作为生产者，利用 Masscan 对目标 IP 进行全端口（1-65535）高速扫描。为防止触发防火墙，脚本会对开放端口数量进行筛选（<=150个），并将结果推入队列。

**第二级（指纹识别）**：作为消费者，启动多个 Nmap 进程从队列获取任务，仅针对 Masscan 发现的开放端口进行服务版本探测 (-sV)，大幅减少了 Nmap 的耗时。

**第三级（web指纹信息收集）**

Web 信息：使用 requests 获取网页 Title、状态码及 Server 头。

SSH 审计：利用 paramiko 连接 SSH 端口，通过捕获异常来判断服务端是否支持“密码登录”或仅限“密钥登录”。

TLS 信息：使用 ssl 库提取 SSL/TLS 证书版本及过期时间。

**告警与存储**：

结果处理进程将所有扫描数据（IP、服务、产品版本、Web指纹等）统一写入 CSV 文件。

内置高危规则匹配（如 Docker、Redis、MongoDB 等），一旦发现高危服务或端口，立即通过企业微信 Webhook 发送实时告警。<br>

**运行环境**：
  Linux、Windows<br>
  Python 3.6以上<br>
  masscan 1.3.2 <br>
  nmap 7.93及以上<br>
  
**使用方法**
```
  1、安装masscan、nmap
    sudo apt-get update
    sudo apt-get install nmap masscan

  2、创建python3虚拟环境
    python3 -m venv venv
    cd venv/
    source venv/bin/activate
    pip install -r requirements.txt
```

## 3、python-nmap

![image](https://github.com/bigzeroo/nmap_Multiprocess-scanning/blob/main/scan1.jpg)<br>
![image](https://github.com/bigzeroo/nmap_Multiprocess-scanning/blob/main/scan2.jpg)<br>




   
  
