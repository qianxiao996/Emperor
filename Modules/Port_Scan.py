#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import queue
import re
import threading  # 导入线程相关模块
from socket import *
from Modules.Chrome_Screen import Chrome_Screen
import eventlet
import ipaddr
import requests
from scapy.layers.l2 import Ether, ARP
from scapy.sendrecv import srp1
requests.packages.urllib3.disable_warnings()
from PyQt5.QtCore import QThread, pyqtSignal

lock = threading.Lock() #申请一个锁
# scan(['blog.qianxiao996.cn','129.204.113.202'], [443,80,8081], 22,1)
# exit()

signs_rules=[
'http|^HTTP.*',
'ssh|SSH-2.0-OpenSSH.*',
'ssh|SSH-1.0-OpenSSH.*',
'netbios|^\x79\x08.*BROWSE',
'netbios|^\x79\x08.\x00\x00\x00\x00',
'netbios|^\x05\x00\x0d\x03',
'netbios|^\x83\x00',
'netbios|^\x82\x00\x00\x00',
'netbios|\x83\x00\x00\x01\x8f',
'backdoor-fxsvc|^500 Not Loged in',
'backdoor-shell|GET: command',
'backdoor-shell|sh: GET:',
'bachdoor-shell|[a-z]*sh: .* command not found',
'backdoor-shell|^bash[$#]',
'backdoor-shell|^sh[$#]',
'backdoor-cmdshell|^Microsoft Windows .* Copyright .*>',
'db2|.*SQLDB2RA',
'dell-openmanage|^\x4e\x00\x0d',
'finger|^\r\n	Line	  User',
'finger|Line	 User',
'finger|Login name: ',
'finger|Login.*Name.*TTY.*Idle',
'finger|^No one logged on',
'finger|^\r\nWelcome',
'finger|^finger:',
'finger|^must provide username',
'finger|finger: GET: ',
'ftp|^220.*\n331',
'ftp|^220.*\n530',
'ftp|^220.*FTP',
'ftp|^220 .* Microsoft .* FTP',
'ftp|^220 Inactivity timer',
'ftp|^220 .* UserGate',
'http|^HTTP/0.',
'http|^HTTP/1.',
'http|<HEAD>.*<BODY>',
'http|<HTML>.*',
'http|<html>.*',
'http|<!DOCTYPE.*',
'http|^Invalid requested URL ',
'http|.*<?xml',
'http|^HTTP/.*\nServer: Apache/1',
'http|^HTTP/.*\nServer: Apache/2',
'http-iis|.*Microsoft-IIS',
'http-iis|^HTTP/.*\nServer: Microsoft-IIS',
'http-iis|^HTTP/.*Cookie.*ASPSESSIONID',
'http-iis|^<h1>Bad Request .Invalid URL.</h1>',
'http-jserv|^HTTP/.*Cookie.*JServSessionId',
'http-tomcat|^HTTP/.*Cookie.*JSESSIONID',
'http-weblogic|^HTTP/.*Cookie.*WebLogicSession',
'http-vnc|^HTTP/.*VNC desktop',
'http-vnc|^HTTP/.*RealVNC/',
'ldap|^\x30\x0c\x02\x01\x01\x61',
'ldap|^\x30\x32\x02\x01',
'ldap|^\x30\x33\x02\x01',
'ldap|^\x30\x38\x02\x01',
'ldap|^\x30\x84',
'ldap|^\x30\x45',
'smb|^\0\0\0.\xffSMBr\0\0\0\0.*',
'msrdp|^\x03\x00\x00\x0b',
'msrdp|^\x03\x00\x00\x11',
'msrdp|^\x03\0\0\x0b\x06\xd0\0\0\x12.\0$',
'msrdp|^\x03\0\0\x17\x08\x02\0\0Z~\0\x0b\x05\x05@\x06\0\x08\x91J\0\x02X$',
'msrdp|^\x03\0\0\x11\x08\x02..}\x08\x03\0\0\xdf\x14\x01\x01$',
'msrdp|^\x03\0\0\x0b\x06\xd0\0\0\x03.\0$',
'msrdp|^\x03\0\0\x0b\x06\xd0\0\0\0\0\0',
'msrdp|^\x03\0\0\x0e\t\xd0\0\0\0[\x02\xa1]\0\xc0\x01\n$',
'msrdp|^\x03\0\0\x0b\x06\xd0\0\x004\x12\0',
'msrdp-proxy|^nmproxy: Procotol byte is not 8\n$',
'msrpc|^\x05\x00\x0d\x03\x10\x00\x00\x00\x18\x00\x00\x00\x00\x00',
'msrpc|\x05\0\r\x03\x10\0\0\0\x18\0\0\0....\x04\0\x01\x05\0\0\0\0$',
'mssql|^\x04\x01\0C..\0\0\xaa\0\0\0/\x0f\xa2\x01\x0e.*',
'mssql|^\x05\x6e\x00',
'mssql|^\x04\x01\x00\x25\x00\x00\x01\x00\x00\x00\x15.*',
'mssql|^\x04\x01\x00.\x00\x00\x01\x00\x00\x00\x15.*',
'mssql|^\x04\x01\x00\x25\x00\x00\x01\x00\x00\x00\x15.*',
'mssql|^\x04\x01\x00.\x00\x00\x01\x00\x00\x00\x15.*',
'mssql|^\x04\x01\0\x25\0\0\x01\0\0\0\x15\0\x06\x01.*',
'mssql|^\x04\x01\x00\x25\x00\x00\x01.*',
'telnet|^xff\xfb\x01\xff\xfb\x03\xff\xfb\0\xff\xfd.*',
'mssql|;MSSQLSERVER;',
'mysql|.*mysql.*',
'mysql|.*mysql_native_password.*/g',
'mysql|^\x19\x00\x00\x00\x0a',
'mysql|^\x2c\x00\x00\x00\x0a',
'mysql|hhost \'',
'mysql|khost \'',
'mysql|mysqladmin',
'mysql|whost \'',
'mysql-blocked|^\(\x00\x00',
'mysql-secured|this MySQL',
'mongodb|^.*version.....([\.\d]+)',
'nagiosd|Sorry, you \(.*are not among the allowed hosts...',
'nessus|< NTP 1.2 >\x0aUser:',
'oracle-tns-listener|\(ERROR_STACK=\(ERROR=\(CODE=',
'oracle-tns-listener|\(ADDRESS=\(PROTOCOL=',
'oracle-dbsnmp|^\x00\x0c\x00\x00\x04\x00\x00\x00\x00',
'oracle-https|^220- ora',
'oracle-rmi|\x00\x00\x00\x76\x49\x6e\x76\x61',
'oracle-rmi|^\x4e\x00\x09',
'postgres|Invalid packet length',
'postgres|^EFATAL',
'rlogin|login: ',
'rlogin|rlogind: ',
'rlogin|^\x01\x50\x65\x72\x6d\x69\x73\x73\x69\x6f\x6e\x20\x64\x65\x6e\x69\x65\x64\x2e\x0a',
'rpc-nfs|^\x02\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00',
'rpc|\x01\x86\xa0',
'rpc|\x03\x9b\x65\x42\x00\x00\x00\x01',
'rpc|^\x80\x00\x00',
'rsync|^@RSYNCD:.*',
'smux|^\x41\x01\x02\x00',
'snmp-public|\x70\x75\x62\x6c\x69\x63\xa2',
'snmp|\x41\x01\x02',
'socks|^\x05[\x00-\x08]\x00',
'ssh|^SSH-',
'ssh|^SSH-.*openssh',
'ssl|^..\x04\0.\0\x02',
'ssl|^\x16\x03\x01..\x02...\x03\x01',
'ssl|^\x16\x03\0..\x02...\x03\0',
'ssl|SSL.*GET_CLIENT_HELLO',
'ssl|-ERR .*tls_start_servertls',
'ssl|^\x16\x03\0\0J\x02\0\0F\x03\0',
'ssl|^\x16\x03\0..\x02\0\0F\x03\0',
'ssl|^\x15\x03\0\0\x02\x02\.*',
'ssl|^\x16\x03\x01..\x02...\x03\x01',
'ssl|^\x16\x03\0..\x02...\x03\0',
'sybase|^\x04\x01\x00',
'telnet|^\xff\xfd',
'telnet|Telnet is disabled now',
'telnet|^\xff\xfe',
'tftp|^\x00[\x03\x05]\x00',
'http-tomcat|.*Servlet-Engine',
'uucp|^login: password: ',
'vnc|^RFB.*',
'webmin|.*MiniServ',
'webmin|^0\.0\.0\.0:.*:[0-9]',
'websphere-javaw|^\x15\x00\x00\x00\x02\x02\x0a']



PROBES=[
'\r\n\r\n',
'GET / HTTP/1.0\r\n\r\n',
'GET / \r\n\r\n',
'\x01\x00\x00\x00\x01\x00\x00\x00\x08\x08',
'\x80\0\0\x28\x72\xFE\x1D\x13\0\0\0\0\0\0\0\x02\0\x01\x86\xA0\0\x01\x97\x7C\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0',
'\x03\0\0\x0b\x06\xe0\0\0\0\0\0',
'\0\0\0\xa4\xff\x53\x4d\x42\x72\0\0\0\0\x08\x01\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x40\x06\0\0\x01\0\0\x81\0\x02PC NETWORK PROGRAM 1.0\0\x02MICROSOFT NETWORKS 1.03\0\x02MICROSOFT NETWORKS 3.0\0\x02LANMAN1.0\0\x02LM1.2X002\0\x02Samba\0\x02NT LANMAN 1.0\0\x02NT LM 0.12\0',
'\x80\x9e\x01\x03\x01\x00u\x00\x00\x00 \x00\x00f\x00\x00e\x00\x00d\x00\x00c\x00\x00b\x00\x00:\x00\x009\x00\x008\x00\x005\x00\x004\x00\x003\x00\x002\x00\x00/\x00\x00\x1b\x00\x00\x1a\x00\x00\x19\x00\x00\x18\x00\x00\x17\x00\x00\x16\x00\x00\x15\x00\x00\x14\x00\x00\x13\x00\x00\x12\x00\x00\x11\x00\x00\n\x00\x00\t\x00\x00\x08\x00\x00\x06\x00\x00\x05\x00\x00\x04\x00\x00\x03\x07\x00\xc0\x06\x00@\x04\x00\x80\x03\x00\x80\x02\x00\x80\x01\x00\x80\x00\x00\x02\x00\x00\x01\xe4i<+\xf6\xd6\x9b\xbb\xd3\x81\x9f\xbf\x15\xc1@\xa5o\x14,M \xc4\xc7\xe0\xb6\xb0\xb2\x1f\xf9)\xe8\x98',
'\x16\x03\0\0S\x01\0\0O\x03\0?G\xd7\xf7\xba,\xee\xea\xb2`~\xf3\0\xfd\x82{\xb9\xd5\x96\xc8w\x9b\xe6\xc4\xdb<=\xdbo\xef\x10n\0\0(\0\x16\0\x13\0\x0a\0f\0\x05\0\x04\0e\0d\0c\0b\0a\0`\0\x15\0\x12\0\x09\0\x14\0\x11\0\x08\0\x06\0\x03\x01\0',
'< NTP/1.2 >\n',
'< NTP/1.1 >\n',
'< NTP/1.0 >\n',
'\0Z\0\0\x01\0\0\0\x016\x01,\0\0\x08\0\x7F\xFF\x7F\x08\0\0\0\x01\0 \0:\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\04\xE6\0\0\0\x01\0\0\0\0\0\0\0\0(CONNECT_DATA=(COMMAND=version))',
'\x12\x01\x00\x34\x00\x00\x00\x00\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01\x02\x00\x1c\x00\x0c\x03\x00\x28\x00\x04\xff\x08\x00\x01\x55\x00\x00\x00\x4d\x53\x53\x51\x4c\x53\x65\x72\x76\x65\x72\x00\x48\x0f\x00\x00',
'\0\0\0\0\x44\x42\x32\x44\x41\x53\x20\x20\x20\x20\x20\x20\x01\x04\0\0\0\x10\x39\x7a\0\x01\0\0\0\0\0\0\0\0\0\0\x01\x0c\0\0\0\0\0\0\x0c\0\0\0\x0c\0\0\0\x04',
'\x01\xc2\0\0\0\x04\0\0\xb6\x01\0\0\x53\x51\x4c\x44\x42\x32\x52\x41\0\x01\0\0\x04\x01\x01\0\x05\0\x1d\0\x88\0\0\0\x01\0\0\x80\0\0\0\x01\x09\0\0\0\x01\0\0\x40\0\0\0\x01\x09\0\0\0\x01\0\0\x40\0\0\0\x01\x08\0\0\0\x04\0\0\x40\0\0\0\x01\x04\0\0\0\x01\0\0\x40\0\0\0\x40\x04\0\0\0\x04\0\0\x40\0\0\0\x01\x04\0\0\0\x04\0\0\x40\0\0\0\x01\x04\0\0\0\x04\0\0\x40\0\0\0\x01\x04\0\0\0\x02\0\0\x40\0\0\0\x01\x04\0\0\0\x04\0\0\x40\0\0\0\x01\0\0\0\0\x01\0\0\x40\0\0\0\0\x04\0\0\0\x04\0\0\x80\0\0\0\x01\x04\0\0\0\x04\0\0\x80\0\0\0\x01\x04\0\0\0\x03\0\0\x80\0\0\0\x01\x04\0\0\0\x04\0\0\x80\0\0\0\x01\x08\0\0\0\x01\0\0\x40\0\0\0\x01\x04\0\0\0\x04\0\0\x40\0\0\0\x01\x10\0\0\0\x01\0\0\x80\0\0\0\x01\x10\0\0\0\x01\0\0\x80\0\0\0\x01\x04\0\0\0\x04\0\0\x40\0\0\0\x01\x09\0\0\0\x01\0\0\x40\0\0\0\x01\x09\0\0\0\x01\0\0\x80\0\0\0\x01\x04\0\0\0\x03\0\0\x80\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\x01\x04\0\0\x01\0\0\x80\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\x40\0\0\0\x01\0\0\0\0\x01\0\0\x40\0\0\0\0\x20\x20\x20\x20\x20\x20\x20\x20\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\xff\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xe4\x04\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x7f',
'\x41\0\0\0\x3a\x30\0\0\xff\xff\xff\xff\xd4\x07\0\0\0\0\0\0test.$cmd\0\0\0\0\0\xff\xff\xff\xff\x1b\0\0\0\x01serverStatus\0\0\0\0\0\0\0\xf0\x3f\0'
]

class Port_Scan(QThread):
    _data = pyqtSignal(dict)  # 信号类型 str  更新table
    _num = pyqtSignal(int)  # 信号类型 str  更新进度条
    _count = pyqtSignal(int)  # 信号类型 str  更新进度条总数
    _log = pyqtSignal(str)  # 信号类型 str 更新日志
    def __init__(self, remove_port, logger, ip, port, jp_flag, timeout, threads,chrome_driver,parent=None):
        super(Port_Scan,self).__init__(parent)
        self.stop_flag = 0
        self.remove_port =remove_port
        self.logger =logger
        self.portscan_Queue = queue.Queue()
        self.ip = ip
        self.port =port
        self.count=100
  
        self.jp_flag=jp_flag #跳过主机发现
        self.timeout =timeout
        self.threads =threads
        self.all_port_list=[]
        self.all_ip_list=[]
        self.ipQueue = queue.Queue()
        self.chrome_driver = chrome_driver


    def get_system(self):
        if os.name == 'nt':
            return 'n'
        else:
            return 'c'
    #探测主机存活
    def startPing(self,ip_str):
        # print(ip_str)
        a=0
        shell = ['ping','-{op}'.format(op=self.get_system()),'2',ip_str]
        output = os.popen(' '.join(shell)).readlines()
        for line in list(output):
            if not line:
                continue
            if str(line).upper().find('TTL') >= 0:
                # print("ip: %s is ok " % ip_str)
                a=1
                return a
            else:
                continue
        return a


    #得到-d中的ip列表
    def get_ip_d_list(self,ip):
        ip_list=[]
        #127.0.0.1/24匹配
        remath_1 = r'^(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\/([1-9]|[1-2]\d|3[0-2])$'
        re_result1 =  re.search(remath_1,ip,re.I|re.M)
        #127.0.0.1-222匹配
        remath_2 = r'^(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\-(25[0-5]|2[0-4][0-9]|[0-1]?[0-9]?[0-9])$'
        re_result2 =  re.search(remath_2,ip,re.I|re.M)
        # remath_3 = r'^(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$'
        # re_result3 =  re.search(remath_3,ip)
        if re_result1:
            try:
                ipNet = ipaddr.IPv4Network(re_result1.group())
                for ip in ipNet:
                    ip_list.append(str(ip))
                    # print(isinstance(ip, ipaddr.IPv4Address))
                    # print (str(ip))
                ip_list = ip_list[1:-1]
            except:
                print('Error:IP段设置错误！')
                return
            # print(ip_list)
            # ip = ip.replace('/24','')
            # for i in range(1,255):
            #     ip_list.append(ip[:ip.rfind('.')]+'.'+str(i))
        elif re_result2:
            ip_addr = re_result2.group()
            ip_start = ip_addr.split('.')[-1].split('-')[0]
            ip_end = ip_addr.split('.')[-1].split('-')[1]
            # print(ip_start,ip_end)
            if int(ip_start)>int(ip_end):
                numff =ip_start
                ip_start= ip_end
                ip_end = numff
            for i in range(int(ip_start), int(ip_end)+1):
                ip_list.append(ip[:ip.rfind('.')] + '.' + str(i))
        else:
            ip_list = ip.split()
            # result = re.findall(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", ip)
            # if result:
                # ip_list.extend(result)
            # ip_list.append(re_result3.group())
        # 列表去重
        all_list = []
        for i in ip_list:
            if i not in all_list:
                all_list.append(i)
        return list(filter(None, all_list))  # 去除 none 和 空字符


    #得到端口列表
    def get_port_list(self,port):
        port_list=[]
        if ',' in port and '-' not in port:
            port_list = port.strip().split(',')
        elif ',' not in port and '-' in port:
            port_start = port.split('-')[0]
            port_end = port.split('-')[1]
            if int(port_start)>int(port_end):
                numff =port_start
                port_start= port_end
                port_end = numff
            for i in range(int(port_start), int(port_end)+1):
                port_list.append(str(i).strip())
        elif ',' in port and '-' in port:
            port_list = port.split(',')
            for i in port_list:
                port_list.remove(i)
                port_start = i.split('-')[0]
                port_end = i.split('-')[1]
                if int(port_start) > int(port_end):
                    numff = port_start
                    port_start = port_end
                    port_end = numff
                for i in range(int(port_start), int(port_end) + 1):
                    port_list.append(str(i).strip())
        else:
            port_list = port.split()
        for i in port_list:
            if  int(i) > 65535:
                port_list.remove(i)
        # print(port_list)
        return port_list


    def portScanner(self):
        while True:
            try:
                if self.stop_flag==1:
                    return
                elif self.portscan_Queue.qsize()==0 and len(self.all_ip_list)>0 :
                    for i in self.all_port_list :
                        if self.stop_flag!=1:
                        # print(port_list)
                            self.portscan_Queue.put(self.all_ip_list[0]+':'+str(i))
                        else:
                            self.portscan_Queue.queue.clear()
                            return
                    del(self.all_ip_list[0])
                else:
                    Banner=''
                    title=''
                    screen_img=''
                    eventlet.monkey_patch(thread=False, time=True)
                    with eventlet.Timeout(60, False):
                        if self.portscan_Queue.empty():  # 队列空就结束
                            break
                        ip_port = self.portscan_Queue.get()  # 从队列中取出
                        host = ip_port.split(':')[0]
                        port = ip_port.split(':')[1]
                        # pbar.set_description(Fore.BLUE+'[*] Scanning:'+host+' '+port)  # 修改进度条描述
                        self._num.emit((1))  # 计算结果完成后，发送结果
                        # print(host,port)
                        try:

                            tcp = socket(AF_INET, SOCK_STREAM)
                            tcp.settimeout(int(self.timeout))  # 如果设置太小，检测不精确，设置太大，检测太慢
                            # print(host,port)
                            result = tcp.connect_ex((host, int(port)))  # 效率比connect高，成功时返回0，失败时返回错误码
                            # print(port+"success")
                            if result == 0:
                                url_address=''
                                tcp.send("test".encode(encoding='gbk'))
                                try:
                                    Banner = tcp.recv(1024)
                                    try:
                                        Banner = Banner.decode("gbk")
                                    except:
                                        # print(str(Banner.decode("raw_unicode_escape").strip().encode("utf-8")))
                                        Banner=str(Banner.decode("raw_unicode_escape").strip().encode("utf-8"))
                                    service=self.matchbanner(Banner,signs_rules)
                                    if service=="Unknown":
                                        return_Data  = self.scanservice(host, port,timeout)
                                        service = return_Data[0]
                                        if return_Data[1]!='':
                                            Banner =return_Data[1]
                                        if return_Data[2]:
                                            title =return_Data[2]
                                    # print(Banner)
                                    # print(service)
                                except:
                                    return_Data = self.scanservice(host, port, timeout)
                                    service = return_Data[0]
                                    if return_Data[1]!='':
                                        Banner =return_Data[1]
                                    if return_Data[2]:
                                        title = return_Data[2]
                                if service =='http' or  service =='HTTP'  or  service =='HTTPS'  or  service =='https' :
                                    try:
                                        if  service =='https' or  service =='HTTPS':
                                            url_address = 'https://'+host.strip()+':'+port.strip()
                                        else:
                                            url_address = 'http://'+host.strip()+':'+port.strip()
                                        html = requests.get(url_address,verify = False)
                                        if not html:
                                            html = requests.post(url_address,verify = False)
                                        html.encoding = html.apparent_encoding
                                        if html.status_code==404:
                                            title="404 Not Found"
                                        elif html.text:
                                            Banner = html.text
                                            # print (html.text)
                                            re_data = re.search(r'<title>(.+)</title>',html.text,re.I|re.M)
                                            if re_data:
                                                title = re_data.group().replace('<title>','').replace('</title>','').replace('<TITLE>','').replace('</TITLE>','')
                                            # print(html.text)
                                            elif "404 Not Found" in html.text:
                                                title="404 Not Found"
                                            elif "Page Not Found" in html.text:
                                                title="Page Not Found"
                                            else:
                                                title=''
                                        else:
                                            title=''

                                        # print (title)
                                    except Exception as e:
                                        # print(e)
                                        title = ""

                                        # Banner =Banner
                                #获取网页截图的base64
                                try:
                                    if self.chrome_driver:
                                        screen_img = Chrome_Screen(self.chrome_driver, url_address).main()

                                except:
                                    pass

                                # Banner=''
                                self.out_result(host,port,'Opened',Banner,service,url_address,title,screen_img)
                            else:
                                pass
                        except Exception as e:
                            self.logger.error(str(e) + '----' + str(e.__traceback__.tb_lineno) + '行')
                            continue
                        finally:
                            try:
                                tcp.close()
                            except:
                                pass
                    continue
            except Exception as e:
                self.logger.error(str(e) + '----' + str(e.__traceback__.tb_lineno) + '行')
                continue
            i
    def scanservice(self, host, port, timeout):
        Banner = ''
        title = ''
        service = 'Unknown'
        for probe in PROBES:
            try:
                sd = socket(AF_INET, SOCK_STREAM)
                sd.settimeout(int(timeout))
                sd.connect((host, int(port)))
                sd.send(probe.encode(encoding='utf-8'))
            except:
                continue
            try:
                result = sd.recv(1024)
                try:
                    result = result.decode("gbk")
                except:
                    result=str(result.decode("raw_unicode_escape").strip().encode("utf-8"))
                # print(result)
                if ("<title>400 Bad Request</title>" in result and "https" in result) or (
                        "<title>400 Bad Request</title>" in result and "HTTPS" in result):
                    service = 'https'
                    title = result
                    break
                service = self.matchbanner(result, signs_rules)
                if service != 'Unknown':
                    Banner = result
                    break

            except Exception as e:
                self.logger.error(str(e) + '----' + str(e.__traceback__.tb_lineno) + '行')
                continue
        if service != "Unknown":
            pass
        else:
            service = self.get_server(str(port))
        return service, Banner, title

    def get_server(self,port):
        SERVER = {
            'FTP': '21',
            'SSH': '22',
            'Telnet': '23',
            'SMTP': '25',
            'DNS': '53',
            'DHCP': '68',
            'HTTP': '80',
            'TFTP': '69',
            'HTTP': '8080',
            'POP3': '995',
            'NetBIOS': '139',
            'IMAP': '143',
            'HTTPS': '443',
            'SNMP': '161',
            'LDAP': '489',
            'SMB': '445',
            'SMTPS': '465',
            'Linux R RPE': '512',
            'Linux R RLT': '513',
            'Linux R cmd': '514',
            'Rsync': '873',
            'IMAPS': '993',
            'Proxy': '1080',
            'JavaRMI': '1099',
            'Lotus': '1352',
            'MSSQL': '1433',
            'MSSQL': '1434',
            'Oracle': '1521',
            'PPTP': '1723',
            'cPanel': '2082',
            'CPanel': '2083',
            'Zookeeper': '2181',
            'Docker': '2375',
            'Zebra': '2604',
            'MySQL': '3306',
            'Kangle': '3312',
            'RDP': '3389',
            'SVN': '3690',
            'Rundeck': '4440',
            'GlassFish': '4848',
            'PostgreSql': '5432',
            'PcAnywhere': '5632',
            'VNC': '5900',
            'CouchDB': '5984',
            'varnish': '6082',
            'Redis': '6379',
            'Weblogic': '7001',
            'Kloxo': '7778',
            'Zabbix': '8069',
            'RouterOS': '8291',
            'Elasticsearch': '9200',
            'Elasticsearch': '9300',
            'Zabbix': '10050',
            'Zabbix': '10051',
            'Memcached': '11211',
            'MongoDB': '27017',
            'MongoDB': '28017',
            'Hadoop': '50070'
        }
        for k, v in SERVER.items():
            if v == port:
                return k
        return 'Unknown'

    def matchbanner(self,banner,slist):
        for item in slist:
            item = item.split('|')
            p=re.compile(item[1])
            if p.search(banner)!=None:
                return item[0]
        return 'Unknown'
    def out_result(self,host,port,zhuangtai,Banner='None',service='Unknown',url_address='',title='',screen_img=''):
        lock.acquire()  #加锁
        if zhuangtai=='Opened':
            data= {"Host":host.strip(),"Port":port.strip(),"Service":service.strip(),"Title":title,"Banner":Banner,"screen_img":screen_img}
            self._data.emit((data))  # 计算结果完成后，发送结果
        else:
            pass
        lock.release()  #执行完 ，释放锁
        #创建线程
    def diff_of_two_list(self,list1,list2):
        for value in list2:
            try:
                # value = int(value)
                if value in list1:
                    list1.remove(value)
            except:
                pass
        return list1

    def run(self):
        try:
            self._log.emit('正在检测主机存活')
            self.ip = self.ip.split("\n")
            all_ip_list=[]
            for ip in self.ip:
                all_ip_list.extend( self.get_ip_d_list(ip))
            # #列表去重
            # for i in ip_list:
            #     if i not in self.all_ip_list:
            #         self.all_ip_list.append(i)
            if (self.jp_flag == 1):
                self.all_ip_list = all_ip_list
            else:
                try:
                    for ip in all_ip_list:
                        self.ipQueue.put(ip)
                    ip_threads=[]
                    if self.ipQueue.qsize()>50:
                        ip_threads_num=50
                    else:
                        ip_threads_num=self.ipQueue.qsize()
                    for i in range(int(ip_threads_num)):
                        i = threading.Thread(target=self.ipScanner, args=())
                        ip_threads.append(i)
                    for i in ip_threads:
                        i.start()
                    for j in ip_threads:
                        j.join()
                except Exception as e:
                    self._log.emit(str(e))
                    pass
            if self.stop_flag == 1:
                self._log.emit('停止扫描')
                return
            if len(self.all_ip_list) > 0:
                self._log.emit('正在创建队列')
                all_port_list = self.get_port_list(self.port)
                try:
                    self.remove_port = self.remove_port.split(",")
                    self.all_port_list = self.diff_of_two_list(all_port_list, self.remove_port)
                except:
                    self._log.emit("排除端口格式出错！")
                    return
                self.scan(int(self.threads), timeout)
            else:
                self._log.emit('NO IP is alive')
                self._log.emit('停止扫描')
        except Exception as e:
            self.logger.error(str(e) + '----' + str(e.__traceback__.tb_lineno) + '行')
    def  scan(self,threadNum,timeout):
        try:
            self.portscan_Queue.queue.clear()
            if(threadNum>len(self.all_port_list)):
                threadNum=len(self.all_port_list)
            kkk = int(threadNum/len(self.all_port_list ))+1
            self.count = len(self.all_ip_list) * len(self.all_port_list)
            self._log.emit(
                'IP数量:%s,端口:%s,线程:%s' % (len(self.all_ip_list), len(self.all_port_list), self.threads))
            self._log.emit("正在创建队列...")
            try:
                for ip in range(0,kkk):
                    # print(self.all_ip_list[ip])
                    if not self.stop_flag:
                        self.all_ip_list[ip] = self.all_ip_list[ip].replace("https://",'').replace("http://",'').split("/")[0]
                        for port in self.all_port_list :
                            # print(self.all_ip_list[ip]+':'+str(port))
                            self.portscan_Queue.put(self.all_ip_list[ip]+':'+str(port))
                        self.all_ip_list.remove(self.all_ip_list[ip])
            except:
                pass
            self.threads_list = []  # 线程列表
            if self.portscan_Queue.qsize() > 0:
                try:
                    self._count.emit(self.count)
                    if self.threads > self.portscan_Queue.qsize():
                        self.threads = self.portscan_Queue.qsize()
                    self._log.emit('扫描开始')
                    for i in range(self.threads):
                        i = threading.Thread(target=self.portScanner, args=())
                        self.threads_list.append(i)
                    for t in self.threads_list:  # 启动线程
                        t.start()
                    for t in self.threads_list:  # 阻塞线程，等待线程结束
                        t.join()
                except Exception as e:
                    self.logger.error(str(e) + '----' + str(e.__traceback__.tb_lineno) + '行')
                    
            self._log.emit('扫描结束')
        except Exception as e:
            self.logger.error(str(e) + '----' + str(e.__traceback__.tb_lineno) + '行')

    def ipScanner(self):
        while True:
            if self.ipQueue.empty()  or self.stop_flag == 1:  # 队列空就结束
                break
            ip = self.ipQueue.get()  # 从队列中取出
            try:
                result = self.arp_scan(ip)
                if result:
                    self._log.emit("[ARP]IP:" + ip + " alive")
                    self.all_ip_list.append(ip)
                else:
                    if (self.startPing(ip)):
                        self._log.emit("[ICMP]IP:" + ip + " alive")
                        self.all_ip_list.append(ip)
            except:

                if (self.startPing(ip)):
                    self._log.emit("[ICMP]IP:" + ip + " alive")
                    self.all_ip_list.append(ip)

    def arp_scan(self, ip):

        for ipFix in range(1, 255 + 1):
            # 构造本网段的ip。如：192.168.50.20

            # 组合协议包
            # 通过 '/' 可叠加多个协议层(左底层到右上层)，如Ether()/IP()/UDP()/DNS()
            arpPkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
            # 发送arp请求，并获取响应结果。设置1s超时。
            res = srp1(arpPkt, timeout=1, verbose=0)

            # 如果ip存活
            if res:
                return 1

            # 如果ip不存活
            else:
                return 0