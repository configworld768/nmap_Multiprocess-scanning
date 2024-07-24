## 写的比较乱，只是可以跑起来。。。。<br>
# nmap_Multiprocess-scanning
nmap Multi-process scanning masscan、nmap多进程扫描脚本<br>
## 脚本扫描逻辑
  1）从ip.txt文件中加载ip，放在一个列表里，列表作为masscan多进程的参数，masscan每扫描完一个ip会放入到 nmap_queue队列里，等待nmap进程去获取任务 （masscan启动的进程数在pool=Pool(num)设置，一般根据cpu的核数量来设置）<br>
  2) nmap进程数在range那里设置，nmap扫描完之后解析json结果并分析且高危端口或服务告警并记录扫描结果到csv文件，web端口信息使用httpx和tlsx来获取，比如指纹、证书信息等<br>

## 1、运行环境：
  Linux<br>
  Python 3.6以上

## 2、安装masscan 1.3.2 及以上版本、nmap 7.93及以上

## 3、python-nmap

4、install httpx（https://github.com/projectdiscovery/httpx）<br>
   install tlsx (https://github.com/projectdiscovery/tlsx)<br>

![image](https://github.com/bigzeroo/nmap_Multiprocess-scanning/blob/main/scan.png)

   
  
