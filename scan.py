# coding=utf-8
# author: huowuzhao
import subprocess
import os
import random
import string
import json 
import time 
import csv
import traceback
import requests
import socket
import nmap
import datetime
from multiprocessing import Queue, Process, Pool, Manager
from queue import Empty as QueueEmpty
from mylogging import Logger


class OperationFile(object):
    '''
    操作文件方法，包含打开文件和关闭文件
    '''
    def __init__(self,filename,listname) -> None:
        self.filename = filename
        self.listname = listname

    def open_file(self,filename,listname):
        with open(filename,'r') as ipfile:
            ip1 = ipfile.readlines()
            for i in ip1:
                listname.append(i.strip().replace('\\',''))
        #print(listname)

    def save_file(self,filename,listname):
        str2 = '\n'
        f_pubdomain = open(filename, 'w')
        f_pubdomain.write(str2.join(listname))
        f_pubdomain.close()

# 判断结果存储文件夹是否存在
dirs = '/usr/local/src/scan_result/'
file_date = str(datetime.date.today())
result_dirs = dirs + file_date
if not os.path.exists(result_dirs):
    os.makedirs(result_dirs)
# 将 ip.txt 中的 ip 地址加载到 iplist 列表中
iplist = []
noalive_ip = []
domainlst = []
cdn_iplst = []
# cdn ip和失效解析的域名
notScanDomainIp = [] 
# 获取上次扫描结果里记录的不存活的ip,对上次识别到的不存活的ip只扫1-15000,25066,25552这些端口
last_noalivip=dirs + str(datetime.date.today() - datetime.timedelta(days=1)) + '/'+'noalive_ip.txt'
try:
    operationfile = OperationFile('filename','listname')
    if os.path.getsize(last_noalivip):
        operationfile.open_file(last_noalivip,noalive_ip)      
except FileNotFoundError:
    operationfile.open_file('/usr/local/src/nmap_scan/assets/noalive_ip.txt',noalive_ip)
operationfile.open_file('/usr/local/src/nmap_scan/assets/ip.txt',iplist)   
operationfile.open_file('/usr/local/src/nmap_scan/assets/subdomain.txt',domainlst)
operationfile.open_file('/usr/local/src/nmap_scan/assets/cdn_ip.txt',cdn_iplst)
operationfile.open_file('/usr/local/src/nmap_scan/assets/cdn_falseDomain.txt',notScanDomainIp)

def get_ip(domain):
    ''' 
    从域名中解析 ip 地址,找出不在 iplist 中的域名添加到 iplist 中
    '''
    # 存储公网域名
    pub_domain = []
    try:
        if domain not in notScanDomainIp:
            address = socket.getaddrinfo(domain, 'http')
            domain_ip = address[0][4][0]
            if domain_ip != None:
                if not domain_ip.startswith(
                        ('172.16.','192.168.','10.','172.27','127.0.','172.23.','8.8.','172.28','172.29','221.','58.218.','220.','223.')):
                    pub_domain.append(domain) 
                    # 获取不在 ip.txt 和 cdn_iplst 中的 ip 地址
                    if domain_ip not in iplist and domain_ip not in cdn_iplst:  
                        iplist.append(domain_ip)
                        # print(domain_ip)
            return domain_ip
    except Exception as e:
        log.error("存在错误: %s " % str(e))
        
    operationfile.open_file(result_dirs + '/' + 'pub_domain.txt',pub_domain)

class GetWebInfo(object):
    '''
    获取 title、status_code、tls等相关信息
    '''
    def __init__(self,url,first_url) -> None:
        self.url = url
        self.first_url = first_url

    def check_webinfo(self,url):
        ''' 
        获取http协议端口的title,状态码,ip对应的域名信息 
        '''
        title1 = ''
        status_code = ''
        ip_domain = ''
        first_url = ''
        scheme = ''
        location = ''
        method = ''
        content_type = ''
        content_length = ''
        httpx_json = result_dirs+'/'+'httpx.json' 
        subprocess.getstatusoutput('timeout 10 echo {}|httpx -tls-probe -json -o {}'.format(url,httpx_json))  
        if os.path.getsize(httpx_json):
            with open(httpx_json, 'r') as http_json:
                http_lst = http_json.readlines()
                log.info('http_lst: %s' % http_lst)
                first_url = json.loads(http_lst[0])['url']
                log.info('first_url: %s' % first_url)
                for status in http_lst:
                    http_dict = json.loads(status)
                    log.info(http_dict)
                    if 'tls-grab' in http_dict and 'dns_names' in http_dict['tls-grab'] and str(http_dict['tls-grab']['dns_names']) not in ip_domain:
                        ip_domain = ip_domain + str(http_dict['tls-grab']['dns_names'])
                    if 'title' in http_dict:  
                        title1 = http_dict['title'] + ';' + title1
                    if 'status-code' in http_dict:
                        status_code = int(http_dict['status-code'])

                    if 'scheme' in http_dict.keys():
                        scheme = http_dict['scheme'] + ';' + scheme
                    if 'location' in http_dict.keys():
                        location = http_dict['location'] + ';' + location
                    if 'method' in http_dict.keys():
                        method = http_dict['method'] + ';' + method
                    if 'content-type' in http_dict.keys():
                        content_type = http_dict['content-type'] + ';' + content_type
                    if 'ontent-length' in http_dict.keys():
                        content_length = http_dict['ontent-length'] + ';' + content_length


                    if 'url' in http_dict and http_dict['url'] not in url:
                        if http_dict['url'] not in url_lst:
                            url_lst.append(first_url)
                        url = url + ',' + http_dict['url']
        return title1,status_code,ip_domain,first_url,scheme,location,method,content_type,content_length

    def check_tls(self,first_url):
        ''' 
        获取IP的证书相关信息,这里可以做证书过期监控 
        '''
        tls_version = ''
        domain_supplier = ''
        cipher = ''
        expire_date = ''
        tls_type = ''
        tlsx_json = result_dirs+'/'+'tlsx.json'   
        subprocess.getstatusoutput('timeout 10 tlsx -u {} -json -o {} -silent'.format(first_url,tlsx_json))
        if os.path.getsize(tlsx_json):
            with open(tlsx_json, 'r') as tlsx_result:
                tlsx_lst = tlsx_result.readlines()
                for tls in tlsx_lst:
                    tlsx_dict = json.loads(tls)
                    log.info(tlsx_dict)
                    if 'tls_version' in tlsx_dict:
                        tls_version = tlsx_dict['tls_version']
                    if 'issuer_dn' in tlsx_dict:
                        domain_supplier = tlsx_dict['issuer_dn']
                    elif 'subject_dn' in tlsx_dict:
                        domain_supplier = tlsx_dict['subject_dn']   
                    if 'cipher' in tlsx_dict:
                        cipher = tlsx_dict['cipher']
                    if 'not_after' in tlsx_dict:
                        expire_date = tlsx_dict['not_after']
                    if 'self_signed' in tlsx_dict and tlsx_dict['self_signed'] == True:
                        tls_type = '自签名证书' 
        return tls_version,domain_supplier,cipher,expire_date,tls_type


def checkSshAuth(sship_port):
    ''' 
    检查ssh的登录方式 
    '''
    try:
        ssh_res = subprocess.getstatusoutput('hydra -w 3 -l redis -p test ssh://{}'.format(sship_port))
        if 'not support password authentication' in ssh_res[1]:
            sshAuth = '秘钥登录'
        elif 'valid password found' in ssh_res[1]:
            sshAuth = '密码登录'
        elif 'timeout' in ssh_res[1]:
            sshAuth = '连接超时'
        else:
            sshAuth = 'unknow'
    except Exception as e:
        sshAuth = 'unknow'

    return sshAuth


def check_vul_port(ip,nm_resultInfo,writer):
    ''' 
    检测高危端口、扫描结果写入 csv 文件 
    '''
    # 高危服务
    vul_service = ['Docker','oracle-tns','Oracle TNS listener','MySQL','MongoDB','redis','Redis key-value store','java-rmi','Java RMI','HashiCorp Consul agent','docker','Memcached','rtsp','mongodb','mongod','ajp13','Apache Jserv','cslistener','zookeeper','Zookeeper','postgresql','PostgreSQL DB','ftp','vsftpd','vnc','VNC','Cowboy httpd','RabbitMQ']
    # 高危端口
    vul_port = [9200,9201,9300,2375,2376,27017,8500,8501,1099,1433,9000]
    # 已发现的高危端口但无法整改加白，防止重复告警
    white_port = []
     
    if ip in nm_resultInfo['scan'] and 'tcp' in nm_resultInfo['scan'][ip]:
        for port in nm_resultInfo['scan'][ip]['tcp'].keys():
            if nm_resultInfo['scan'][ip]['tcp'][port]['state'] == 'open':
                url = ip + ':' + str(port)

                # httpx 获取 http 协议的状态码和 title
                port_service_lst = ['ssh','tcpwrapped']
                if nm_resultInfo['scan'][ip]['tcp'][port]['name'] not in port_service_lst:  # 这种肯定不是http协议的端口，不需要做端口 http 信息获取,减少检测时间
                    title1,status_code,ip_domain,first_url,scheme,location,method,content_type,content_length = getwebinfo.check_webinfo(url) 
                else:
                    title1,status_code,ip_domain,first_url,scheme,location,method,content_type,content_length = '','','','','','','','',''
                
                # 获取 ip 对应的域名信息
                if first_url != '':                    
                    tls_version,domain_supplier,cipher,expire_date,tls_type = getwebinfo.check_tls(first_url)
                else:
                    tls_version = ''
                    domain_supplier = ''
                    cipher = ''
                    expire_date = ''
                    tls_type = ''
                    log.info('ip + ":" + str(port): %s' % ip + ':' + str(port))
                                    
                # 扫描结果写入 csv 文件
                host = ip
                hostname = nm_resultInfo['scan'][ip]['hostnames'][0]['name']
                name = nm_resultInfo['scan'][ip]['tcp'][port]['name']
                product = nm_resultInfo['scan'][ip]['tcp'][port]['product'] + ' ' + nm_resultInfo['scan'][ip]['tcp'][port]['version']
                extrainfo = nm_resultInfo['scan'][ip]['tcp'][port]['extrainfo']
                #version = nm_resultInfo['scan'][ip]['tcp'][port]['version']
                cpe = nm_resultInfo['scan'][ip]['tcp'][port]['cpe']
                
                # 判断 ssh是密码登录还是秘钥登录
                sshAuth = ''
                if name == 'ssh':
                    sship_port = host + ':' + str(port)
                    sshAuth = checkSshAuth(sship_port)
                    if sshAuth == '密码登录':
                        ssh_alert = f'[端口检测][配置错误]发现公网IP存在ssh密码登录 ' + '\n' + 'IP: ' + host + '\n' + '端口: ' + str(sship_port) + '\n' + 'ip归属: ' + subprocess.getstatusoutput("curl cip.cc/{}|head -2|tail -1".format(ip))[1].split('\n')[-1].replace('\t','')
                        qiwei_alert.send_msg(ssh_alert)
                
                # 写入 csv 文件
                writer.writerow(
                    [host, ip_domain, hostname, 'tcp', port, 'open', name, product, sshAuth, first_url,title1, status_code,scheme,location,method,content_type,content_length,tls_version,domain_supplier,cipher,expire_date,tls_type,
                        extrainfo, cpe])
                
                # 开始判断高危服务端口
                if 'product' in nm_resultInfo['scan'][ip]['tcp'][port]:
                    if nm_resultInfo['scan'][ip]['tcp'][port]['product'] in vul_service or nm_resultInfo['scan'][ip]['tcp'][port]['name'] in vul_service:
                        try:
                            domain_info = json.loads(subprocess.getstatusoutput('echo https://{}|httpx -tls-probe -json -silent'.format(ip))[1].split('\n')[0])['tls-grab']['dns_names']
                        except Exception as e:
                            domain_info = ''
                        if nm_resultInfo['scan'][ip]['tcp'][port]['product'] in vul_service and \
                                nm_resultInfo['scan'][ip]['tcp'][port]['product'] != '':
                            port_service = nm_resultInfo['scan'][ip]['tcp'][port]['product']
                            port_version = nm_resultInfo['scan'][ip]['tcp'][port]['version']
                            portinfo = f'[端口检测][配置错误]发现高危端口开放在公网! ' + '\n' + 'IP: ' + ip + '\n' + '端口: ' + str(
                                port) + '\n' + '服务: ' + port_service + '\n' + '版本: ' + port_service + ' ' + port_version + '\n' + '与该IP相关联的域名信息: ' + str(domain_info) + '\n' + 'ip归属' + subprocess.getstatusoutput("curl cip.cc/{}|head -2|tail -1".format(ip))[1].split('\n')[-1].replace('\t','')
                            log.info(portinfo)
                            if (ip+':'+str(port)) not in white_port: 
                                qiwei_alert.send_msg(portinfo)
                                
                        if nm_resultInfo['scan'][ip]['tcp'][port]['product'] == '' and port in vul_port and \
                                nm_resultInfo['scan'][ip]['tcp'][port]['name'] in vul_service:
                            port_service = 'unknow service'
                            port_name = nm_resultInfo['scan'][ip]['tcp'][port]['name']
                            portinfo = f'[端口检测][配置错误]发现高危端口开放在公网! ' + '\n' + 'IP: ' + ip + '\n' + '端口: ' + str(
                                port) + '\n' + '服务: ' + name + '\n' + '版本: ' + ' '  + '\n' + '与该IP相关联的域名信息: ' + str(domain_info) + '\n' + 'ip归属' + subprocess.getstatusoutput("curl cip.cc/{}|head -2|tail -1".format(ip))[1].split('\n')[-1].replace('\t','')
                            log.info(portinfo)
                            if (ip+':'+str(port)) not in white_port: 
                                qiwei_alert.send_msg(portinfo)
        

class Scan(object):
    ''' 
    nmap 扫描方法和 masscan 扫描方法
    '''
    def __init__(self, name, queue) -> None:
        self.name = name
        self.queue = queue

    def mass_scan(self, value):
        ''' 
        masscan 扫描后 put 到队列里 
        '''
        try:
            ran_str = ''.join(random.sample(string.ascii_letters + string.digits,6))
            mass_json = result_dirs+'/'+ '%s.json' % ran_str  
            portlst = []
            if value not in noalive_ip:
                input_mas = 'masscan -oJ {} {} -p 1-65535 --wait 0 --max-rate 3000'.format(mass_json,value)
            else:
                input_mas = 'masscan -oJ {} {} -p 1-15000,25552,25066 --wait 0 --max-rate 3000'.format(mass_json,value)
            subprocess.getstatusoutput(input_mas)
            if os.path.getsize(mass_json):
                f = open(mass_json)
                res = json.loads(f.read())
                f.close()
                for i in res:
                    portlst.append(str(i['ports'][0]['port']))
                # 这里做判断是因为开放端口过多,nmap 会报端口参数过长的错误,超过 100 个端口放弃 nmap 扫描,正常服务器不会开100个端口
                if len(portlst) > 100 or len(portlst) < 1:  
                    str1 = ''     
                else:
                    str1 = ','.join(portlst)
                    to_nmap_value = (value,str1)
                    queue.put(to_nmap_value)
                    portlst.clear()
                    log.info("Process putter put {}".format(to_nmap_value))
            else:
                log.error("{} not alive".format(value))
            subprocess.getstatusoutput('rm -f %s' % mass_json)
        except QueueEmpty:
            log.error("iplst 队列空了!")


    def nmap_scan(self,name, queue):
        ''' 
        消费 masscan put 到队列的ip、端口数据 
        '''
        try:
            log.info('Son process %s' % name)
            while True:
                try:
                    value = queue.get(True, 300)
                    ip,masscan_port = value
                    log.info("Process getter get {}".format(value))
                    log.warning("当前 queue 队列中还有 {} 个对象:".format(str(queue.qsize())))
                    nm_resultInfo = nm.scan(ip, masscan_port)
                    value1 = (ip,json.dumps(nm_resultInfo))
                    nmap_queue.put(value1)
                    log.info(nm_resultInfo)
                except QueueEmpty:
                    log.error("队列空了!")
                    break
        except EOFError:
            log.error("nmap 退出报错了!")

def get_webinfo(webinfo,nmap_queue):
    ''' 
    消费getter put 到nmap_queue 的数据,获取web信息进程 
    '''
    log.info('Son process %s' % webinfo)
    csv_filename = '{}-port_scan.csv'.format(file_date)
    result_filename = result_dirs + '/' + csv_filename 
    csvfile = open(result_filename, 'w', encoding='utf-8-sig')
    writer = csv.writer(csvfile)
    writer.writerow(
        ['host', '域名', 'hostname', 'protocol', 'port', 'state', 'name', 'product', 'sshAuth', 'url', 'title', 'status_code','scheme','location','method','content_type','content_length','tls_version','domain_supplier',
        'cipher','expire_date','tls_type','extrainfo', 'cpe'])
    while True:
        try:
            nm_value = nmap_queue.get(True, 150)
            log.warning("当前 nmap_queue 队列中还有 {} 个对象:".format(str(nmap_queue.qsize())))
            ip,nm_resultInfo_str = nm_value
            nm_resultInfo = json.loads(nm_resultInfo_str)
            check_vul_port(ip,nm_resultInfo,writer)
        except QueueEmpty:
            log.info("队列空了!")
            if queue.qsize() == 0:   # 判断 nmap 的队列是否为空，如果为空的话 nmap 扫描已结束 
                csvfile.close()   
                url_file = result_dirs + '/' + 'url_lst.txt'
                operationfile.save_file(url_file,url_lst)
                # 通过 iplist 和已扫描存活的IP差集取不存活IP 列表
                alive_ip_lst = subprocess.getstatusoutput("cat %s |awk -F, '{print $1}'|sort -n|uniq -c|sort -n|awk '{print $2}'|grep -v host" % result_filename)[1].split('\n')
                no_alive_ip = list(set(iplist).difference(set(alive_ip_lst)))
                operationfile.save_file(result_dirs + '/' + 'noalive_ip.txt',no_alive_ip) 
                qiwei_alert.post_file(result_filename)
                break
            else:
                continue

class ReportAlert(object):
    ''' 
    企微告警、扫描结果csv文件发送到企微
    '''
    def __init__(self) -> None:
        self.webhook = f'https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=XXX'
        #self.webhook = f'https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=XXX'
        self.id_url = f'https://qyapi.weixin.qq.com/cgi-bin/webhook/upload_media?key=XXX&type=file'
        #self.id_url = f'https://qyapi.weixin.qq.com/cgi-bin/webhook/upload_media?key=XXX&type=file'
    
    def send_msg(self,content):
        ''' 企微告警 '''

        data1 = json.dumps({"msgtype": "text", "text": {"content": content, "mentioned_list": ["XXX"]}})
        r = requests.post(self.webhook, data1, auth=('Content-Type', 'application/json'))
        log.info(r.json)
        log.info(r.status_code)
        return r.status_code
    
    def post_file(self, file):
        ''' 扫描结束发送扫描结果 csv 文件到企业微信群 '''

        data = {'file': open(file, 'rb')}
        response = requests.post(url=self.id_url, files=data)
        log.info(response.text)
        json_res = response.json()
        media_id = json_res['media_id']
        data = {"msgtype": "file",
                "file": {"media_id": media_id}
                }
        result = requests.post(url=self.webhook, json=data)
        return (result)

if __name__ == '__main__':
    log = Logger('logger')
    manager = Manager()
    # 保存 masscan 扫描结果队列
    queue = manager.Queue()
    # 保存 nmap 扫描结果的队列
    nmap_queue = manager.Queue()
    # nmap 扫描
    nm = nmap.PortScanner()
    # 企业微信告警
    qiwei_alert = ReportAlert()
    getwebinfo = GetWebInfo('url','first_url')
    not_alive_ip = []
    url_lst = []
    
    # 需要启动几个 masscan 和 nmap 扫描，修改range() 和 Pool() 里的值
    try:
        # 实例化 6 个 nmap 扫描对象,用于下面的启动多进程
        for i in range(6):
            obj = 'nm' + str(i)
            obj = Scan("Putter",queue)
            Process(target=obj.nmap_scan, args=("Putter", queue,)).start()

        '''
        解析域名里的ip地址
        for domain in domainlst:
            get_ip(domain)
        '''
        # 启动获取端口 web 信息的进程，并写文件到 csv 或 mysql 中
        webinfo_process = Process(target=get_webinfo, args=("webinfo",nmap_queue))
        webinfo_process.start()

        # masscan 扫描引入了进程池，启动 4 个 masscan 扫描进程
        pool = Pool(4)
        pool.map(obj.mass_scan,iplist)
        while True:
            if queue.qsize() == 0 and nmap_queue.qsize() == 0:  
                time.sleep(300)
                pool.close()  # 关闭进程池，不再接受新的进程
                pool.join()
                break

    except KeyboardInterrupt:
        log.error("\nKeyboardInterrupt Detected.")
        print("Exiting...")
        log.error("Exiting...")
        exit(0)
