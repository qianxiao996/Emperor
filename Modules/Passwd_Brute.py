# coding=utf-8
import ftplib
import imaplib
import os
import poplib
import frozen_dir
import re
import smtplib
import ssl
import sys
import telnetlib
import time

import pymongo
import requests

from nmb.NetBIOS import NetBIOS
from socket import *

import cx_Oracle
import eventlet
import paramiko

import threading
import queue


import ipaddr
import pymysql

import wmi
from PyQt5.QtCore import QThread, pyqtSignal
import pymssql
from pymssql import _mssql
from pymssql import _pymssql
from smb.SMBConnection import SMBConnection
import psycopg2


class Passwd_Brute(QThread):
    """该线程用于计算耗时的累加操作"""
    _data = pyqtSignal(dict)  # 信号类型 str
    _log_data = pyqtSignal(str)  # 信号类型 str
    _max = pyqtSignal(int)
    _count = pyqtSignal(int)  # 信号类型 str  更新进度条总数


    def __init__(self,Mainwindows,__Logger,ip, username, passwd, moren_dict,scan_port,one_user,timeout,threads,service_list,parent=None):
        super(Passwd_Brute,self).__init__(parent)
        self.Mainwindows = Mainwindows
        self.__Logger = __Logger
        self.ip = ip
        self.username = username
        self.passwd = passwd
        self.moren_dict = moren_dict
        self.scan_port = scan_port
        self.one_user =one_user
        self.timeout = timeout
        self.threads = threads
        self.service_list = service_list
        self.portscan_Queue = queue.Queue()
        self.pwdscan_Queue = queue.Queue()
        self.all_scan_task=[]
        self.stop_flag =0
        self.username_list=[]
        self.passwd_list=[]
        self.threads_list = []
        self.all_service_dict = {}
        self.remove_service =[]
    def run(self):
        all_count=0
        if os.path.exists(self.ip):
            self.ip_list = self.get_ip_f_list(self.ip)
        else:
            self.ip_list = self.get_ip_d_list(self.ip)
        if not len(self.ip_list)>0:
            self._log_data.emit('未获取到IP地址')  # 计算结果完成后，发送结果
            self._log_data.emit('扫描结束')  # 计算结果完成后，发送结果
            return
        sql = 'select * from passwd_brute'
        sql_list = self.Mainwindows.sql_search(sql, 'dict')
        if self.scan_port:
            for ip in self.ip_list:
                for service in self.service_list:
                    for sql_service in sql_list:
                        if sql_service['Service']==service:
                            saaaa =ip + ':' + service+':'+sql_service['Port']
                            # print(saaaa)
                            self.portscan_Queue.put(saaaa)
                            break
            # quit()
            # port_threads = self.threads
            port_threads=300
            if port_threads > self.portscan_Queue.qsize():
                port_threads = self.portscan_Queue.qsize()
            for i in range(port_threads):
                i = threading.Thread(target=self.portScanner, args=())
                self.threads_list.append(i)
            self._log_data.emit('开始扫描端口')  # 计算结果完成后，发送结果
            self._max.emit(self.portscan_Queue.qsize())
            # self.Mainwindows.Ui.progressBar_passwd_brute_jindu.setMaximum()
            for t in self.threads_list:  # 启动线程
                t.start()
            for t in self.threads_list:  # 阻塞线程，等待线程结束
                t.join()
            if self.stop_flag:
                self._log_data.emit('扫描结束')
            self.threads_list=[]
        else:
            for ip in self.ip_list:
                for service in self.service_list:
                    for sql_service in sql_list:
                        if sql_service['Service'] == service:
                            saaaa = ip + ':' + service + ':' + sql_service['Port']
                            self.all_scan_task.append(saaaa)
        if len(self.all_scan_task)<=0:
            self._log_data.emit('没有端口存活')
            self._log_data.emit('扫描结束')  # 计算结果完成后，发送结果
            return
        if not self.moren_dict:
            if  os.path.exists(self.username):
                self.username_list = self.get_file(self.username)

            else:
                self.username_list.append(self.username)
                # return
            if  os.path.exists(self.passwd):
                self.passwd_list = self.get_file(self.passwd)
            else:
                self.passwd_list.append(self.passwd)

                # return
            if len(self.username_list) <= 0 or  len(self.passwd_list) <= 0:
                self._log_data.emit('用户名或密码文件为空')  # 计算结果完成后，发送结果
                self._log_data.emit('扫描结束')  # 计算结果完成后，发送结果
                return
            else:
                for service in self.service_list:
                    temp_list = {}
                    temp_list['username'] = self.username_list
                    temp_list['passwd'] = self.passwd_list
                    all_count += len(self.username_list) * len(self.passwd_list)
                    self.all_service_dict[service] = temp_list

        else:
            if self.stop_flag==1:
                self.stop()
                return
            #使用默认密码
            for service in self.all_scan_task:
                service= service.split(":")[1]
                for sql_service in sql_list:
                    if sql_service['Service'] == service:
                        temp_list = {}
                        # print(os.path.abspath(os.curdir))
                        username_list = self.get_file(sql_service['Username'])
                        if len(username_list)<=0:
                            self._log_data.emit("未获取到%s服务用户名字典"%service)
                        temp_list['username'] = username_list
                        passwd_list =  self.get_file(sql_service['Password'])
                        if len(passwd_list)<=0:
                            self._log_data.emit("未获取到%s服务密码字典"%service)
                        temp_list['passwd'] = passwd_list
                        all_count+=len(passwd_list)*len(username_list)
                        self.all_service_dict[service]  =temp_list
                        break
        self._max.emit(all_count)
        if (self.threads > all_count):
            self.threads = all_count
        self._log_data.emit(
            "共进行%s次扫描 线程:%s 超时:%s" % (str(all_count),self.threads,self.timeout))  # 计算结果完成后，发送结果
        if all_count > 10000:
            kkk = int(self.threads / all_count) + 1
            self.pwdscan_Queue.queue.clear()
            if kkk>len(self.all_service_dict):
                kkk=len(self.all_service_dict)
            for ip in range(0, kkk):
                # print(self.all_ip_list[ip])
                if not self.stop_flag:
                    single_scan_list = self.all_scan_task[ip].split(":")
                    # print(single_scan_list)

                    for username in self.all_service_dict[single_scan_list[1]]['username']:
                        username =username.replace('空','')
                        for passwd in  self.all_service_dict[single_scan_list[1]]['passwd'] :
                            passwd = passwd.replace('%user%',username).replace('空','')
                            queue_data = self.all_scan_task[ip]+":"+username+":"+passwd
                            # print(queue_data)
                            self.pwdscan_Queue.put(queue_data)
                    self.all_scan_task.remove(self.all_scan_task[ip])
                else:
                    self.stop()
                    return
        else:
            for i in self.all_scan_task:
                if not self.stop_flag:
                    single_scan_list = i.split(":")
                    # print(single_scan_list)
                    for username in self.all_service_dict[single_scan_list[1]]['username']:
                        username = username.replace('空', '')
                        for passwd in self.all_service_dict[single_scan_list[1]]['passwd']:
                            passwd = passwd.replace('%user%', username).replace('空', '')
                            queue_data = i+ ":" + username + ":" + passwd
                            # print(queue_data)
                            self.pwdscan_Queue.put(queue_data)
                    self.all_scan_task.remove(i)

        # print(self.all_scan_task)
        # self._data.emit({'Error_Info': str(e)})
        if self.pwdscan_Queue.qsize() > 0:
            # self.Scanner_Task()
            self._log_data.emit('扫描开始')
            for i in range(self.threads):
                i = threading.Thread(target=self.Scanner_Task, args=())
                self.threads_list.append(i)
            for t in self.threads_list:  # 启动线程
                t.start()
            for t in self.threads_list:  # 阻塞线程，等待线程结束
                t.join()
            self._log_data.emit('扫描结束')
        else:
            self._log_data.emit('没有扫描任务')  # 计算结果完成后，发送结果
            self._log_data.emit('扫描结束')  # 计算结果完成后，发送结果



    def Scanner_Task(self):
        while True:
            try:

                if self.stop_flag == 1:
                    self.stop()
                    return

                elif self.pwdscan_Queue.qsize() == 0 and len(self.all_scan_task) > 0:
                    single_scan_list = self.all_scan_task[0].split(":")
                    for username in self.all_service_dict[single_scan_list[1]]['username']:
                        if self.stop_flag != 1:
                            username = username.replace('空', '')
                            for passwd in self.all_service_dict[single_scan_list[1]]['passwd']:
                                passwd = passwd.replace('%user%', username).replace('空', '')
                                queue_data = self.all_scan_task[0]+ ":" + username + ":" + passwd
                                # print(queue_data)
                                self.pwdscan_Queue.put(queue_data)
                        else:
                            self.stop()
                            return

                    del (self.all_scan_task[0])
                else:
                    self._count.emit((1))  # 计算结果完成后，发送结果
                    eventlet.monkey_patch(thread=False, time=True)
                    with eventlet.Timeout(self.timeout, False):
                        if self.pwdscan_Queue.empty():  # 队列空就结束
                            break
                        single_data = self.pwdscan_Queue.get()  # 从队列中取出
                        ip = single_data.split(':')[0]
                        service = single_data.split(':')[1]
                        port = single_data.split(':')[2]
                        username = single_data.split(':')[3]
                        passwd = single_data.split(':')[4]
                        # print(service)
                        if service not in self.remove_service:
                            try:
                                try:
                                    obj = getattr(self, service+'_scan',0)
                                    if obj:
                                        obj(ip,int(port),username,passwd)
                                    else:
                                        self._log_data.emit("无法获取方法："+service+'_scan')
                                except Exception as e:
                                    self.__Logger.error(str(e) + '----' + str(e.__traceback__.tb_lineno) + '行')
                                    obj = getattr(self, service + '_scan', 0)
                                    if obj:
                                        obj(ip,int(port),username,passwd)
                                    else:
                                        pass
                            except:
                                self.__Logger.error(str(e) + '----' + str(e.__traceback__.tb_lineno) + '行')

            except Exception as e:
                self.__Logger.error(str(e) + '----' + str(e.__traceback__.tb_lineno) + '行')

    def get_ip_d_list(self, ip):
        ip_list = []
        # 127.0.0.1/24匹配
        remath_1 = r'^(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\/([1-9]|[1-2]\d|3[0-2])$'
        re_result1 = re.search(remath_1, ip, re.I | re.M)
        # 127.0.0.1-222匹配
        remath_2 = r'^(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\-(25[0-5]|2[0-4][0-9]|[0-1]?[0-9]?[0-9])$'
        re_result2 = re.search(remath_2, ip, re.I | re.M)
        # remath_3 = r'^(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$'
        # re_result3 =  re.search(remath_3,ip)
        if re_result1:
            try:
                ipNet = ipaddr.IPv4Network(re_result1.group())
                for ip in ipNet:
                    ip_list.append(str(ip))
                ip_list = ip_list[1:-1]
            except:
                self._log_data.emit('IP段设置错误')
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
            if int(ip_start) > int(ip_end):
                numff = ip_start
                ip_start = ip_end
                ip_end = numff
            for i in range(int(ip_start), int(ip_end) + 1):
                ip_list.append(ip[:ip.rfind('.')] + '.' + str(i))
        elif re.match(
                    r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$",ip):
            ip_list = ip.strip().split()
        # 列表去重
        all_list = []
        for i in ip_list:
            if i not in all_list:
                all_list.append(i)
        return list(filter(None, all_list))  # 去除 none 和 空字符

    def get_ip_f_list(self,file):
        all_list =[]
        file = open(file,'r',encoding= 'utf-8')
        for line in file:
            all_list =all_list+  self.get_ip_d_list(line)
        file.close()
        return list(filter(None, all_list))  # 去除 none 和 空字符
    def get_file(self,file):
        if self.moren_dict:
            # dict_file = sys.path[0] + '/' + file
            # print(dict_file)
            dict_file =frozen_dir.app_path()+file
            # print(dict_file)
            if  os.path.exists(dict_file):
                file =dict_file
                all_list = []
                file = open(file, 'r', encoding='utf-8')
                for line in file:
                    all_list.append(line.strip())
                file.close()
                return list(filter(None, all_list))  # 去除 none 和 空字符
            else:
                return []
    def portScanner(self):
        while True:
            try:
                self._count.emit((1))  # 计算结果完成后，发送结果
                if self.stop_flag==1:
                    self.stop()
                    return
                else:
                    eventlet.monkey_patch(thread=False, time=True)
                    with eventlet.Timeout(self.timeout, False):
                        if self.portscan_Queue.empty():  # 队列空就结束
                            break
                        ip_port = self.portscan_Queue.get()  # 从队列中取出
                        host = ip_port.split(':')[0]
                        port = ip_port.split(':')[2]
                        # print(host,port)
                        try:
                            tcp = socket(AF_INET, SOCK_STREAM)
                            tcp.settimeout(3)  # 如果设置太小，检测不精确，设置太大，检测太慢
                            # print(host,port)
                            result = tcp.connect_ex((host, int(port)))  # 效率比connect高，成功时返回0，失败时返回错误码
                            # print(port+"success")
                            if result == 0:
                                self._log_data.emit("%s:%s 端口开放" % (host,port))  # 计算结果完成后，发送结果
                                self.all_scan_task.append(ip_port)
                            else:
                                pass
                        except Exception as e:
                            self.__Logger.error(str(e) + '----' + str(e.__traceback__.tb_lineno) + '行')
                            continue
                        finally:
                            try:
                                tcp.close()
                            except:
                                pass
                    continue
            except Exception as e:
                self.__Logger.error(str(e) + '----' + str(e.__traceback__.tb_lineno) + '行')
                continue
    def ssh_scan(self,ip,port,user,pass_):
        try:
            time_start = time.time()
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(hostname=ip, port=int(port), username=user, password=pass_, timeout=self.timeout,allow_agent=False,look_for_keys=False)

            try:
                stdin, stdout, stderr = ssh.exec_command('whoami')  # stdout 为正确输出，stderr为错误输出，同时是有1个变量有值
                data = stdout.read().decode('utf-8')
                ssh.close()
            except:
                time_end = time.time()
                self.out_result(ip, port, 'ssh', user, pass_, '', (time_end - time_start) * 1000)
                return
            time_end = time.time()
            self.out_result(ip,port,'ssh',user,pass_,"whoami:"+data,(time_end - time_start)*1000)
        except Exception as e:
            self.__Logger.error(str(e) + '----' + str(e.__traceback__.tb_lineno) + '行')

        # print(ip,port,username,passwd)
    def ftp_scan(self,ip,port,user,pass_):
        try:
            time_start = time.time()
            ftp=ftplib.FTP()
            ftp.connect(ip,int(port))
            result = ftp.login(user,pass_)
            # result = ftp.retrlines('LIST')
            # print(result)
            ftp.quit()
            time_end = time.time()
            self.out_result(ip,port,'ftp',user,pass_,result,(time_end - time_start)*1000)
        except Exception as e:
            self.__Logger.error(str(e) + '----' + str(e.__traceback__.tb_lineno) + '行')
    def mysql_scan(self,ip,port,user,pass_):
        try:

            time_start = time.time()
            conn = pymysql.connect(ip, user, pass_, 'mysql', int(port))
            cursor = conn.cursor()
            try:
                sql = 'SELECT VERSION()'
                # 执行sql语句
                cursor.execute(sql)
                # 使用fetchone方法获取一个查询结果集
                data = cursor.fetchone()
                cursor.close()
                conn.close()
            except:
                time_end = time.time()
                self.out_result(ip, port, 'mysql', user, pass_, '', (time_end - time_start) * 1000)
                return
            time_end = time.time()
            self.out_result(ip, port, 'mysql', user, pass_, data[0], (time_end - time_start) * 1000)
        except Exception as e:
            self.__Logger.error(str(e) + '----' + str(e.__traceback__.tb_lineno) + '行')
    def sqlserver_scan(self,ip,port,user,pass_):
        try:
            time_start = time.time()
            db = pymssql.connect(server=ip, port=int(port), user=user, password=pass_)
            cursor = db.cursor()
            try:
                SQL = 'SELECT @@VERSION'  # 使用execute()方法执行SQL语句
                cursor.execute(SQL.encode('cp936'))
                # 使用fetall()获取全部数据
                data = cursor.fetchall()
                # 关闭游标和数据库的连接
                cursor.close()
                db.close()
            except:
                time_end = time.time()
                self.out_result(ip, port, 'SQL Server', user, pass_, '', (time_end - time_start) * 1000)
                return
            time_end = time.time()
            self.out_result(ip, port, 'SQL Server', user, pass_, data[0][0], (time_end - time_start) * 1000)
        except Exception as e:
            self.__Logger.error(str(e) + '----' + str(e.__traceback__.tb_lineno) + '行')

    def oracle_scan(self, ip, port, user, pass_):
        time_start = time.time()
        db = cx_Oracle.connect(user, pass_, ip+':'+str(port)+'/orcl')
        try:
            cr = db.cursor()
            sql = "select * from product_component_version"
            cr.execute(sql)
            result = cr.fetchone()
            cr.close()  # 关闭cursor
            db.close()
        except:
            time_end = time.time()
            self.out_result(ip,port,'Oracle',user,pass_,'',(time_end - time_start)*1000)
            return
        time_end = time.time()
        self.out_result(ip, port, 'Oracle', user, pass_, result, (time_end - time_start) * 1000)
    def imap_scan(self, ip, port, user, pass_):
        time_start = time.time()
        conn = imaplib.IMAP4(port=port,host=ip)
        # print('已连接服务器')
        result = conn.login(user, pass_)
        # print('已登陆')
        if "LOGIN completed" in str(result):
            time_end = time.time()
            self.out_result(ip, port, 'IMAP', user, pass_, str(result), (time_end - time_start) * 1000)

    def imap_ssl_scan(self, ip, port, user, pass_):
        time_start = time.time()
        conn = imaplib.IMAP4_SSL(port=port, host=ip)
        # print('已连接服务器')
        result = conn.login(user, pass_)
        if "LOGIN completed" in str(result):
            time_end = time.time()
            self.out_result(ip, port, 'IMAP_SSL', user, pass_, str(result), (time_end - time_start) * 1000)

    def memcached_scan(self, ip, port, user, pass_):
        time_start = time.time()
        s = socket(AF_INET, SOCK_STREAM)
        s.connect((ip,int(port)))
        s.send("stats\r\n".encode())
        result = s.recv(1024)
        time_end = time.time()
        if "version" in result.decode():
            if 'memcached' in self.remove_service:
                return
            else:
                self.remove_service.append('memcached')
                self.out_result(ip, port, 'Mongodb', '', '未授权', str(result.decode()), (time_end - time_start) * 1000)
            return


    def mongodb_scan(self, ip, port, user, pass_):
        time_start = time.time()
        mongo_client = pymongo.MongoClient(host=ip, port=port)
        try:
            # result = mongo_client.server_info()
            db_list = mongo_client.list_database_names()
            time_end = time.time()
            if 'mongodb' in self.remove_service:
                return
            else:
                self.remove_service.append('mongodb')
                self.out_result(ip, port, 'Mongodb', '', '未授权', str(db_list), (time_end - time_start) * 1000)
            return
        except Exception as e:
            if "not authorized" in str(e):
                db = mongo_client.admin
                try:
                    db.authenticate(user, pass_)
                    db_list = mongo_client.list_database_names()
                    # print(db_list)
                    time_end = time.time()
                    self.out_result(ip, port, 'Mongodb', user, pass_, str(db_list), (time_end - time_start) * 1000)
                except:
                    pass
        mongo_client.close()

    def pop3_scan(self, ip, port, user, pass_):
        time_start = time.time()
        # 连接到POP3服务器:
        server = poplib.POP3(ip, port,timeout=self.timeout)
        # print(server.getwelcome())
        server.user(user)
        server.pass_(pass_)
        result = ('Message: %s. Size: %s' % server.stat())
        # 关闭连接:
        server.quit()
        time_end = time.time()
        self.out_result(ip, port, 'POP3', user, pass_, str(result), (time_end - time_start) * 1000)


    def pop3_ssl_scan(self, ip, port, user, pass_):
        time_start = time.time()
        # 连接到POP3服务器:
        server = poplib.POP3_SSL(host=ip, port=port,timeout=self.timeout)
        # print(server.getwelcome())
        server.user(user)
        server.pass_(pass_)
        result = ('Message: %s. Size: %s' % server.stat())
        # 关闭连接:
        server.quit()
        time_end = time.time()
        self.out_result(ip, port, 'POP3_SSL', user, pass_, str(result), (time_end - time_start) * 1000)

    def postgresql_scan(self, ip, port, user, pass_):
        time_start = time.time()
        # 创建连接对象
        try:
            conn = psycopg2.connect(database="postgres", user=user, password=pass_, host=ip, port=port)
            cur = conn.cursor()
        except:
            pass
            return
        try:
            # 获取结果
            cur.execute('select version();')
            results = cur.fetchall()
            # print(results)
            # 关闭练级
            conn.commit()
            cur.close()
            conn.close()
        except:
            time_end = time.time()
            self.out_result(ip, port, 'Postgres', user, pass_, '', (time_end - time_start) * 1000)
            return
        time_end = time.time()
        self.out_result(ip, port, 'Postgres', user, pass_,str(results), (time_end - time_start) * 1000)
    def rdp_scan(self, ip, port, user, pass_):
        conn = wmi.WMI(computer=ip, user=user, password=pass_)
        for sys in conn.Win32_OperatingSystem():
            print("Version:%s" % sys.Caption.encode("UTF8"), "Vernum:%s" % sys.BuildNumber ) # 系统信息

            sys.OSArchitecture.encode("UTF8")  # 系统的位数
            print(sys.NumberOfProcesses)  # 系统的进程数



    def redis_scan(self, ip, port, user, pass_):
        time_start = time.time()
        s = socket(AF_INET, SOCK_STREAM)
        s.connect((ip, int(port)))
        s.send("INFO\r\n".encode())
        result = s.recv(1024)
        s.close()
        if "Authentication" in result.decode():
            time_start = time.time()
            s = socket(AF_INET, SOCK_STREAM)
            s.connect((ip, int(port)))
            s.send(("AUTH %s\r\n" % (pass_)).encode())
            result = s.recv(1024)
            s.close()
            if 'OK' in result.decode():
                time_end = time.time()
                self.out_result(ip,port,'Redis','',pass_,result.decode(),(time_end - time_start)*1000)
                return
            else:
                pass
        elif "redis_version" in result.decode():
            time_end = time.time()
            if 'redis' in self.remove_service:
                return
            else:
                self.remove_service.append('redis')
                self.out_result(ip, port, 'Redis', '', '未授权', result.decode(), (time_end - time_start) * 1000)
            return
    def getBIOSName(self,remote_smb_ip, timeout=30):
        srv_name=''
        try:
            bios = NetBIOS()
            srv_name = bios.queryIPForName(remote_smb_ip, timeout=timeout)
            bios.close()
        except:
            self.__Logger.error("Looking up timeout, check remote_smb_ip again!!")
        finally:

            return srv_name
    def smb_139_scan(self, ip, port, user, pass_):
        # print(user+'===='+pass_+'----'+str(port))
        time_start = time.time()
        try:
            conn = SMBConnection(user, pass_, '', self.getBIOSName(ip)[0], use_ntlm_v2=True,is_direct_tcp=False)
            # is_direct_tcp=True,默认为当direct_tcp=True port=445 。当它是False时，端口应该是139
            conn.connect(ip, port)  # smb服务器地址
            status = conn.auth_result
            # print(status)
            conn.close()
            if status:
                time_end = time.time()
                self.out_result(ip, port, 'SMB', user, pass_, str(status), (time_end - time_start) * 1000)
        except Exception as e:
            pass
            # self.__Logger.error(str(e) + '----' + str(e.__traceback__.tb_lineno) + '行')
    def smb_445_scan(self, ip, port, user, pass_):
        # print(user+'===='+pass_+'----'+str(port))
        time_start = time.time()
        try:
            conn = SMBConnection(user, pass_, '', ip, use_ntlm_v2=True, is_direct_tcp=True)
            # is_direct_tcp=True,默认为当direct_tcp=True port=445 。当它是False时，端口应该是139
            conn.connect(ip, port)  # smb服务器地址
            status = conn.auth_result
            # print(status)
            conn.close()
            if status:
                time_end = time.time()
                self.out_result(ip, port, 'SMB', user, pass_, str(status), (time_end - time_start) * 1000)
        except Exception as e:
            pass
            # self.__Logger.error(str(e) + '----' + str(e.__traceback__.tb_lineno) + '行')

    def smtp_scan(self, ip, port, user, pass_):
        time_start = time.time()
        server = smtplib.SMTP(ip, port)  # 发件人邮箱中的SMTP服务器，端口是25
        restlu= server.login(user, pass_)  # 括号中对应的是发件人邮箱账号、邮箱密码
        server.quit()  # 这句是关闭连接的意思
        if "Authentication successful" in str(restlu):
            time_end = time.time()
            self.out_result(ip, port, 'SMTP', user, pass_, str(restlu), (time_end - time_start) * 1000)



    def smtp_ssl_scan(self, ip, port, user, pass_):
        time_start = time.time()
        server = smtplib.SMTP_SSL(ip, port)  # 发件人邮箱中的SMTP服务器，端口是25
        restlu= server.login(user, pass_)  # 括号中对应的是发件人邮箱账号、邮箱密码
        server.quit()  # 这句是关闭连接的意思
        if "Authentication successful" in str(restlu):
            time_end = time.time()
            self.out_result(ip, port, 'SMTP_SSL', user, pass_, str(restlu), (time_end - time_start) * 1000)

    def telnet_scan(self, ip, port, user, pass_):
        try:
            time_start = time.time()
            # 连接Telnet服务器
            tn = telnetlib.Telnet(ip, port=int(port), timeout=self.timeout)
            tn.set_debuglevel(0)

            # 输入登录用户名

            tn.read_until(b'login: ')
            tn.write(user.encode('ascii') + '\r\n'.encode('ascii'))

            # 输入登录密码
            tn.read_until(b'Password: ')
            tn.write(pass_.encode('ascii') + '\r\n'.encode('ascii'))
            tn.read_some()  # 为result准备数据，可能需要多调用几次才能够获取到服务器返回的信息"Login Failed"
            time.sleep(4)
            result = tn.read_some()  # 这里调用两次，不同的操作系统返回的不一样，AIX linux返回的是invalid
            rex = r'Login incorrect'
            tmp = re.search(rex, result.decode('ascii'))
            # print(result.decode('ascii'))
            tn.close()
            if tmp == None:
                # print(user, pass_)
                time_end = time.time()
                self.out_result(ip, str(port), 'Telnet', user, pass_, result.decode('ascii'), (time_end - time_start) * 1000)
                return
            else:
                return

        except Exception as e:
            pass
    def elasticsearch_scan(self, ip, port, user, pass_):
        time_start = time.time()
        url = "http://" + ip + ":" + str(port) + "/_cat"
        result =requests.get(url,timeout=self.timeout)
        if '/_cat/master' in result.text:
            time_end = time.time()
            self.out_result(ip, str(port), 'Elasticsearch', '', '未授权', result.text,(time_end - time_start) * 1000)
            return
    def cobaltstrike_scan(self, ip, port, user, pass_):
        try:
            time_start = time.time()
            result = None
            conn = Connector()
            conn.open(ip, port)
            payload = bytearray(b"\x00\x00\xbe\xef") + len(pass_).to_bytes(1, "big", signed=True) + bytes(
                bytes(pass_, "ascii").ljust(256, b"A"))
            conn.send(payload)
            if conn.is_connected(): result = conn.receive()
            if conn.is_connected(): conn.close()
            if result == bytearray(b"\x00\x00\xca\xfe"):
                time_end = time.time()
                self.out_result(ip, port, 'Cobalt Strike', user, pass_, '', (time_end - time_start) * 1000)
            else:
                return False

        except Exception as e:
            # print(str(e))
            pass

    def stop(self):
        self.portscan_Queue.queue.clear()
        self.pwdscan_Queue.queue.clear()



    def out_result(self,ip,port,service,user,passwd,result,time):
        if service in self.remove_service:
            return
        else:
            self._data.emit(
                {"ip": ip, "port": str(port), "service": service, "user": user, "pass": passwd, "banner": result,
                 "time": time})
            self._log_data.emit("<a style=\"color:green\">" + ip + '--' + str(
                port) + '--' + service + '---' + user + '--' + passwd + '--success</a>')
            if self.one_user:
                self.remove_service.append(service)

class NotConnectedException(Exception):
    def __init__(self, message=None, node=None):
        self.message = message
        self.node = node


class DisconnectedException(Exception):
    def __init__(self, message=None, node=None):
        self.message = message
        self.node = node

class Connector:
    def __init__(self):
        self.sock = None
        self.ssl_sock = None
        self.ctx = ssl.SSLContext()
        self.ctx.verify_mode = ssl.CERT_NONE
        pass

    def is_connected(self):
        return self.sock and self.ssl_sock

    def open(self, hostname, port):
        self.sock = socket(AF_INET, SOCK_STREAM)
        self.sock.settimeout(10)
        self.ssl_sock = self.ctx.wrap_socket(self.sock)

        if hostname == gethostname():
            ipaddress = gethostbyname_ex(hostname)[2][0]
            self.ssl_sock.connect((ipaddress, port))
        else:
            self.ssl_sock.connect((hostname, port))

    def close(self):
        if self.sock:
            self.sock.close()
        self.sock = None
        self.ssl_sock = None

    def send(self, buffer):
        if not self.ssl_sock: raise NotConnectedException("Not connected (SSL Socket is null)")
        self.ssl_sock.sendall(buffer)

    def receive(self):
        if not self.ssl_sock: raise NotConnectedException("Not connected (SSL Socket is null)")
        received_size = 0
        data_buffer = b""

        while received_size < 4:
            data_in = self.ssl_sock.recv()
            data_buffer = data_buffer + data_in
            received_size += len(data_in)

        return data_buffer
