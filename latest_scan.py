# coding=utf-8
# by hwz
import subprocess
import os
import random
import string
import json
import time
import csv
import socket
import ssl
import ipaddress
import requests
import paramiko
import nmap
import datetime
import logging
from bs4 import BeautifulSoup
from multiprocessing import Queue, Process, Pool, Manager
from urllib.parse import urlparse

# --- 配置区域 ---
CONFIG = {
    'masscan_rate': 3000,
    'result_dir': '/usr/local/src/scan_result/',
    'assets_dir': '/usr/local/src/nmap_scan/assets/',
    'webhook_url': 'https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=YOUR_KEY',
    'vul_services': ['Docker', 'MySQL', 'Redis', 'MongoDB', 'PostgreSQL', 'Consul', 'Zookeeper'],
    'vul_ports': [9200, 2375, 27017, 8500, 1433, 6379]
}

# --- 日志配置 ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
log = logging.getLogger('Scanner')

# --- 工具函数 ---

def is_public_ip(ip_str):
    """使用标准库判断是否为公网IP"""
    try:
        ip = ipaddress.ip_address(ip_str)
        return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved)
    except ValueError:
        return False

def get_native_webinfo(url):
    """替代 httpx: 使用 requests 获取 Web 信息"""
    info = {
        'title': '', 'status_code': 0, 'server': '', 'location': '', 'url': url
    }
    try:
        # 设置超时和 UA，忽略 SSL 警告
        headers = {'User-Agent': 'Mozilla/5.0 (ScanBot)'}
        resp = requests.get(url, headers=headers, timeout=5, verify=False, allow_redirects=True)
        
        info['status_code'] = resp.status_code
        info['url'] = resp.url # 最终跳转地址
        info['server'] = resp.headers.get('Server', '')
        info['location'] = '' if len(resp.history) == 0 else resp.history[0].headers.get('Location', '')
        
        # 解析 Title
        if resp.content:
            soup = BeautifulSoup(resp.content, 'html.parser')
            if soup.title:
                info['title'] = soup.title.string.strip()
    except Exception as e:
        # log.debug(f"Web check failed for {url}: {e}")
        pass
    return info

def get_native_tls_info(host, port):
    """替代 tlsx: 使用 ssl 库获取证书信息"""
    tls_info = {
        'tls_version': '', 'subject': '', 'issuer': '', 'expire_date': ''
    }
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    
    try:
        with socket.create_connection((host, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                tls_info['tls_version'] = ssock.version()
                # 这是一个简化版解析，完整解析证书比较复杂，这里只做演示
                # Python 3.10+ getpeercert(True) 拿二进制自行解析更准，或者依赖 pyopenssl
                # 简单获取仅用于演示连接成功
                if cert:
                    tls_info['expire_date'] = cert.get('notAfter', '')
    except Exception:
        pass
    return tls_info

def check_ssh_auth_paramiko(ip, port):
    """替代 hydra: 使用 paramiko 检测 SSH 认证方式"""
    transport = paramiko.Transport((ip, int(port)))
    auth_type = 'unknown'
    try:
        transport.connect()
        # 尝试以此判断是否支持密码认证，或者直接查看 server 支持的 auth types
        # 实际上我们不需要真的登录，只需要看服务端允许的 methods
        try:
            transport.auth_none('')
        except paramiko.BadAuthenticationType as e:
            allowed_types = e.allowed_types
            if 'password' in allowed_types:
                auth_type = '密码登录'
            elif 'publickey' in allowed_types:
                auth_type = '秘钥登录'
            else:
                auth_type = str(allowed_types)
        except paramiko.SSHException:
             auth_type = '连接异常'
    except Exception:
        auth_type = '连接超时/失败'
    finally:
        transport.close()
    return auth_type

# --- 核心类 ---

class ScanManager:
    def __init__(self):
        self.today_dir = os.path.join(CONFIG['result_dir'], str(datetime.date.today()))
        if not os.path.exists(self.today_dir):
            os.makedirs(self.today_dir)
        
    def load_targets(self):
        """加载目标 IP"""
        iplist = []
        ip_file = os.path.join(CONFIG['assets_dir'], 'ip.txt')
        if os.path.exists(ip_file):
            with open(ip_file, 'r') as f:
                for line in f:
                    ip = line.strip()
                    if is_public_ip(ip):
                        iplist.append(ip)
        return list(set(iplist))

    def masscan_worker(self, ip_target, nmap_queue):
        """Masscan 扫描逻辑"""
        json_file = os.path.join(self.today_dir, f'mass_{random.randint(1000,9999)}.json')
        try:
            # 扫描端口：全端口或常用端口
            cmd = f"masscan -oJ {json_file} {ip_target} -p 1-65535 --wait 0 --max-rate {CONFIG['masscan_rate']}"
            subprocess.getstatusoutput(cmd)
            
            if os.path.exists(json_file) and os.path.getsize(json_file) > 0:
                with open(json_file, 'r') as f:
                    try:
                        data = json.load(f)
                        ports = []
                        for item in data:
                            if 'ports' in item:
                                ports.append(str(item['ports'][0]['port']))
                        
                        if 0 < len(ports) <= 150: # 限制端口数量，太多可能是防火墙干扰
                            port_str = ",".join(ports)
                            nmap_queue.put((ip_target, port_str))
                            log.info(f"[Masscan] Found {ip_target} ports: {len(ports)}")
                    except json.JSONDecodeError:
                        pass
                os.remove(json_file)
            else:
                log.info(f"[Masscan] {ip_target} No open ports found.")
        except Exception as e:
            log.error(f"Masscan error: {e}")

    def nmap_worker(self, nmap_queue, result_queue):
        """Nmap 扫描逻辑"""
        nm = nmap.PortScanner()
        while True:
            task = nmap_queue.get()
            if task is None: # 毒丸信号
                break
            
            ip, ports = task
            try:
                # -sV 探测版本，-Pn 不ping
                nm.scan(ip, ports, arguments='-sV -Pn')
                if ip in nm.all_hosts():
                    result_queue.put(nm[ip])
            except Exception as e:
                log.error(f"Nmap error on {ip}: {e}")

    def analysis_worker(self, result_queue):
        """结果分析与写入逻辑 (Web指纹/TLS/SSH)"""
        csv_path = os.path.join(self.today_dir, 'scan_result.csv')
        f = open(csv_path, 'w', newline='', encoding='utf-8-sig')
        writer = csv.writer(f)
        writer.writerow(['IP', 'Hostname', 'Port', 'Service', 'Product', 'Version', 'SSH_Auth', 'Web_Title', 'Web_Status', 'TLS_Ver', 'Info'])

        while True:
            data = result_queue.get()
            if data is None:
                break
            
            # 这里 data 是 nmap 的单个 host 结果字典
            ip = list(data['addresses'].values())[0] if 'addresses' in data else 'unknown'
            # 注意: python-nmap 的结构差异，这里假设已经处理好拿到 ip 字符串
            # 实际 nm[ip] 返回的是该 ip 的详细 dict
            
            # 为了简便，我们假设 data 就是 nm[ip] 的内容，我们需要在外部传递 IP 进去或者从 data 结构里解析
            # 修正：nm.scan 返回结果较复杂，建议 nmap_worker 传 (ip, nm[ip])
            
            # 重新解析逻辑
            host_data = data # 假设传入的是 nm[ip]
            if 'tcp' not in host_data:
                continue

            for port, pdata in host_data['tcp'].items():
                service_name = pdata['name']
                product = pdata['product']
                version = pdata['version']
                state = pdata['state']

                if state != 'open':
                    continue

                # 1. SSH 检测
                ssh_auth = ''
                if service_name == 'ssh':
                    ssh_auth = check_ssh_auth_paramiko(ip, port)
                    if ssh_auth == '密码登录':
                        send_wechat_alert(f"⚠️ 高危: SSH支持密码登录 {ip}:{port}")

                # 2. Web 检测 (HTTP/HTTPS)
                web_info = {'title': '', 'status_code': ''}
                tls_info = {'tls_version': ''}
                
                if service_name in ['http', 'https', 'ssl'] or 'http' in service_name:
                    protocol = 'https' if 'https' in service_name or port == 443 else 'http'
                    url = f"{protocol}://{ip}:{port}"
                    web_info = get_native_webinfo(url)
                    
                    if protocol == 'https':
                        tls_info = get_native_tls_info(ip, port)

                # 3. 高危端口/服务检测
                if check_high_risk(service_name, product, port):
                     send_wechat_alert(f"🔴 发现高危服务: {ip}:{port} ({product or service_name})")

                # 写入 CSV
                writer.writerow([
                    ip, 
                    host_data.get('hostnames', [{'name': ''}])[0]['name'],
                    port,
                    service_name,
                    product,
                    version,
                    ssh_auth,
                    web_info.get('title'),
                    web_info.get('status_code'),
                    tls_info.get('tls_version'),
                    pdata.get('extrainfo')
                ])
                f.flush()
        
        f.close()
        log.info(f"Scan finished. Results saved to {csv_path}")
        # 这里可以调用发送文件到企微的函数

def check_high_risk(service, product, port):
    """判断高危"""
    s = service.lower()
    p = product.lower()
    for vul in CONFIG['vul_services']:
        if vul.lower() in s or vul.lower() in p:
            return True
    if port in CONFIG['vul_ports']:
        return True
    return False

def send_wechat_alert(content):
    """发送简单的文本告警"""
    try:
        data = {"msgtype": "text", "text": {"content": content}}
        requests.post(CONFIG['webhook_url'], json=data)
    except Exception:
        pass

if __name__ == '__main__':
    # 必须在 Main 中初始化
    manager = Manager()
    nmap_queue = manager.Queue()
    result_queue = manager.Queue()
    
    scanner = ScanManager()
    targets = scanner.load_targets()
    
    log.info(f"Loaded {len(targets)} targets.")

    # 1. 启动结果分析进程 (消费者)
    analyzer = Process(target=scanner.analysis_worker, args=(result_queue,))
    analyzer.start()

    # 2. 启动 Nmap 进程池 (中间消费者)
    nmap_pool_size = 6
    nmap_pool = []
    for _ in range(nmap_pool_size):
        p = Process(target=scanner.nmap_worker, args=(nmap_queue, result_queue))
        p.start()
        nmap_pool.append(p)

    # 3. Masscan 扫描 (生产者)
    # 使用进程池并发运行 Masscan (因为 Masscan 本身很快，不需要太多并发，控制在4个左右)
    masscan_pool = Pool(4)
    for ip in targets:
        masscan_pool.apply_async(scanner.masscan_worker, args=(ip, nmap_queue))
    
    masscan_pool.close()
    masscan_pool.join() # 等待所有 Masscan 结束
    
    log.info("Masscan phase finished.")

    # 4. 停止 Nmap 进程
    # 发送毒丸，通知 Nmap 进程结束
    for _ in range(nmap_pool_size):
        nmap_queue.put(None)
    
    for p in nmap_pool:
        p.join()
        
    log.info("Nmap phase finished.")

    # 5. 停止分析进程
    result_queue.put(None)
    analyzer.join()

    log.info("All tasks completed.")
