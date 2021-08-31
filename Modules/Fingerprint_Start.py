#!/usr/bin/env python
# -*- coding: utf-8 -*-
import queue
import re
import threading  # 导入线程相关模块
from socket import *
from urllib import parse
import hashlib
import BaseInfo
import CyberCalculate
from Modules.Chrome_Screen import Chrome_Screen

import eventlet
import requests
import json

requests.packages.urllib3.disable_warnings()
from PyQt5.QtCore import QThread, pyqtSignal

class Fingerprint_Start(QThread):
    _data = pyqtSignal(dict)  # 信号类型 str  更新table
    _num = pyqtSignal(int)  # 信号类型 str  更新进度条
    _count = pyqtSignal(int)  # 信号类型 str  更新进度条总数
    _log = pyqtSignal(str)  # 信号类型 str 更新日志
    def __init__(self,Mainwindows,url_text, threads, timeout, checkBox_keyword,checkBox_fofa,methods,content_type,parent=None):
        super(Fingerprint_Start,self).__init__(parent)
        self.Mainwindows = Mainwindows
        self.url_list = url_text
        self.threads =threads
        self.timeout=timeout
        self.checkBox_keyword =checkBox_keyword
        self.checkBox_fofa =checkBox_fofa
        self.methods =methods
        self.content_type =content_type
        self.Fingerprint_Queue = queue.Queue()
        self.url_Queue = queue.Queue()
        self.threads_list=[]
        self.stop_flag=0
        self.remove_url_list=[]
    def run(self):
        # sql = "select * from fingerprint_keyword"
        # rule_key_data = self.Mainwindows.sql_search(sql)
        # # print(rule_key_data)
        # for i in rule_key_data:
        #     print(i[1]+"|"+json.dumps(i[2])+"|"+i[3]+"|"+i[5])
        # quit()
        try:
            all_url_list = self.url_list.splitlines()
            self.url_list=[]
            self.url_list_cunhuo=[]
            all_url_list = list(filter(None, all_url_list))  # 去除 none 和 空字符
            for i in all_url_list:
                if "http://" not in i and "https://" not in i:
                    url = "http://"+i
                else:
                    url = i
                self.url_list_cunhuo.append(url)
            self._log.emit('正在进行url存活探测')
            self.url_Queue.queue.clear()
            for i in self.url_list_cunhuo:
                self.url_Queue.put(i)
            if self.threads > self.url_Queue.qsize():
                url_threads = self.url_Queue.qsize()
            else:
                url_threads = self.threads
            self.url_threads_list=[]
            for i in range(url_threads):
                i2 = threading.Thread(target=self.get_url(), args=())
                self.url_threads_list.append(i2)
            for t in self.url_threads_list:  # 启动线程
                t.start()
            for t in self.url_threads_list:  # 阻塞线程，等待线程结束
                t.join()
            self._log.emit('url存活探测完成')
            try:
                if len(self.url_list) == 0:
                    self._log.emit('NO URL')
                    self._log.emit('停止扫描')
                    return
                self._log.emit('共进行%s个url识别...'%len(self.url_list))
                self.Fingerprint_Queue.queue.clear()

                if self.checkBox_keyword:
                    self._log.emit('正在创建综合扫描队列...')
                    self.Fingerprint_Queue.queue.clear()
                    sql = "select * from fingerprint_all where url is not null"
                    rule_ = self.Mainwindows.sql_search(sql, 'dict')
                    for url in self.url_list:
                        if self.stop_flag == 1:
                            self.Fingerprint_Queue.queue.clear()
                            self._log.emit('停止扫描')
                            return
                        for i in rule_:
                            if self.stop_flag == 1:
                                self.Fingerprint_Queue.queue.clear()
                                self._log.emit('停止扫描')
                                return
                            else:

                                self.Fingerprint_Queue.put("all|#|" +url+'|#|'+str(i.get('url')) + "|#|" + str(i.get(
                                    're')) + "|#|" + str(i.get('md5'))+ "|#|" + str(i.get('headers'))+ "|#|" + str(i.get('name')))
                    self._log.emit('开始进行综合识别指纹...')
                    self.scan()
                if self.checkBox_fofa:
                    self._log.emit('正在创建Fofa规则识别队列...')
                    self.Fingerprint_Queue.queue.clear()
                    sql = "select Product,FofaQuery_link,FofaQuery from fingerprint_fofa"
                    rule_ = self.Mainwindows.sql_search(sql,'dict')
                    for url in self.url_list:
                        if self.stop_flag == 1:
                            self.Fingerprint_Queue.queue.clear()
                            self._log.emit('停止扫描')
                            return
                        for i in rule_:
                            if self.stop_flag == 1:
                                self.Fingerprint_Queue.queue.clear()
                                self._log.emit('停止扫描')
                                return
                            else:
                                self.Fingerprint_Queue.put("fofa|#|"+url+"|#|"+i.get('Product')+"|#|"+i.get('FofaQuery_link')+"|#|"+i.get('FofaQuery'))
                    self._log.emit('开始进行FoFa规则识别指纹...')
                    self.scan()
                for url in self.url_list:
                    try:
                        # print( self.remove_url_list)
                        if url  in   self.remove_url_list:
                            continue
                        html = requests.get(url, verify=False, timeout=self.timeout)
                        html.encoding = html.apparent_encoding
                        title = ''
                        re_data = re.search(r'<title>(.+)</title>', html.text, re.I | re.M)
                        if re_data:
                            title = re_data.group().replace('<title>', '').replace('</title>', '').replace('<TITLE>',
                                                                                                           '').replace(
                                '</TITLE>', '')
                        Server = ''
                        if html.headers.get('Server'):
                            Server = html.headers.get('Server')
                        if html.headers.get('X-Powered-By'):
                            Server = Server + "|" + html.headers.get('X-Powered-By')
                        data = {"Type": '', "Url": url, "Name": '', "Title": title, "Server": Server}
                        self._data.emit(data)  # 计算结果完成后，发送结果
                    except:
                        data = {"Type": '', "Url": url, "Name": '', "Title": '地址无法接通', "Server": ''}
                        self._data.emit((data))  # 计算结果完成后，发送结果
                self._data.emit({'end': "扫描结束"})  # 计算结果完成后，发送结果

            except Exception as e:
                self._log.emit(str(e) + '----' + str(e.__traceback__.tb_lineno) + '行')
                return

        except Exception as e:
            self._log.emit(str(e) + '----' + str(e.__traceback__.tb_lineno) + '行')
            pass
            # self.logger.error(str(e) + '----' + str(e.__traceback__.tb_lineno) + '行')

    def scan(self):

        try:

            if self.threads > self.Fingerprint_Queue.qsize():
                self.threads = self.Fingerprint_Queue.qsize()
            self._count.emit(self.Fingerprint_Queue.qsize())
            self._log.emit(
                '请求次数:%s,线程:%s,超时:%s' % (self.Fingerprint_Queue.qsize(), str(self.threads), str(self.timeout)))
            self._log.emit("扫描开始")
            self.threads_list = []
            for i in range(self.threads):
                i2 = threading.Thread(target=self.FingerprintScanner, args=())
                self.threads_list.append(i2)
            for t in self.threads_list:  # 启动线程
                t.start()
            for t in self.threads_list:  # 阻塞线程，等待线程结束
                t.join()
            # self._data.emit({"end":True})  # 计算结果完成后，发送结果
            return
        except Exception as e:
            self._log.emit(str(e) + '----' + str(e.__traceback__.tb_lineno) + '行')


    def FingerprintScanner(self):
        while True:
            try:
                if self.stop_flag==1:
                    return
                else:
                    eventlet.monkey_patch(thread=False, time=True)
                    with eventlet.Timeout(self.timeout, False):
                        if self.Fingerprint_Queue.empty():  # 队列空就结束
                            return
                        data = self.Fingerprint_Queue.get()  # 从队列中取出
                        self._num.emit((1))  # 计算结果完成后，发送结果
                        data = data.split("|#|")
                        # print(data)
                        if data[1]  in self.remove_url_list:
                            continue
                        if data[0]=='all':
                            # md5|#|url|#|path|#|re|#|md5|#|headers|#|name
                            html=''
                            try:
                                html,title,headers,Server = self.http_client(str(data[1] + "/" + data[2]), '',self.methods)
                            except:
                                pass
                            if   html and headers :
                                myhash = hashlib.md5()
                                myhash.update(html)
                                respone_md5 = myhash.hexdigest()
                                if data[4] !='None' and  respone_md5==data[4]:
                                    self.out_result('md5|'+data[2]+'|'+data[4],data[1],data[6],title,Server)
                                    continue
                                #re
                                elif data[3] !='None':
                                    try:
                                        re_result = re.search(data[3], html.decode('utf-8'))
                                        if re_result:
                                        # re.findall(data[3], html)
                                            self.out_result('re|'+data[2]+'|'+data[3],data[1],data[6],title,Server)
                                            continue
                                    except Exception as e:
                                        pass
                                        # print(str(e) + '----' + str(e.__traceback__.tb_lineno) + '行')

                                elif data[5] != 'None':
                                    try:
                                        heades_re = json.loads(data[5])
                                        for ss in heades_re:
                                            if heades_re[ss] in  headers[ss]:
                                                self.out_result('heades|'+data[5]+'|'+data[4], data[1], data[6], title, Server)
                                                continue
                                    except Exception as e:
                                        pass
                                        # print(str(e) + '----' + str(e.__traceback__.tb_lineno) + '行')
                        elif data[0]=='fofa':
                            #fofa|#|url|#|cms_name|#|FofaQuery_link|#|FofaQuery
                            if data[1] !="None" and data[2] !="None" and data[3] !="None" and data[4] !="None" :
                                fofaquery = data[4].lower()
                                fofa_url = data[1]+"/"+data[3]
                                try:
                                    responce = BaseInfo.http_info(fofa_url)
                                    oOperand = {"data": responce}
                                    oCyberCalc = CyberCalculate.CyberCalculate(szHayStack=oOperand, szRule=fofaquery,
                                                                               szSplit='=')
                                    blMatch = oCyberCalc.Calculate()
                                    # print(fofaquery[0])
                                    if blMatch:
                                        # fofa规则匹配
                                        #out_result(type, url, name, title, Server):
                                        self.out_result('fofa|' + data[3] + '|' + data[4], data[1], data[2], responce.get('title'), responce.get('service'))
                                        continue
                                except:
                                    pass
                    continue
            except Exception as e:
                # pass
                # print(str(data[1] + "/" + data[2]),self.methods)
                print(str(e) + '----' + str(e.__traceback__.tb_lineno) + '行')
                # self.logger.error(str(e) + '----' + str(e.__traceback__.tb_lineno) + '行')
                continue

    def http_client(self,url,post,methods,num=1):
        try:
            heards={
                "Content-Type": self.content_type
            }
            html=''
            if methods=='GET':
                html = requests.get(url, verify=False, timeout=self.timeout, data=post,headers=heards)
            if methods == 'POST':
                html = requests.post(url, verify=False, timeout=self.timeout,data=post,headers=heards)
            if methods == 'HEAD':
                html = requests.head(url, verify=False, timeout=self.timeout,data=post,headers=heards)
            html.encoding = html.apparent_encoding
            Banner = html.content
            title=''
            re_data = re.search(r'<title>(.+)</title>', html.text, re.I | re.M)
            if re_data:
                title = re_data.group().replace('<title>', '').replace('</title>', '').replace('<TITLE>', '').replace(
                    '</TITLE>', '')
            # print(html.text)
            Server=''
            if html.headers.get('Server'):
                Server = html.headers.get('Server')
            if html.headers.get('X-Powered-By'):
                Server = Server + "|" + html.headers.get('X-Powered-By')
            return Banner,str(title),html.headers,str(Server)
        except:
            if num==2:
                return
            self.http_client(url, '', methods,2)


    def out_result(self,type,url,name,title,Server):
        try:
            data= {"Type":type,"Url":url,"Name":name,"Title":title,"Server":Server}
            # print(data)
            if url  in self.remove_url_list:
                return
            self._data.emit(data)  # 计算结果完成后，发送结果
            # print(url)
            self.remove_url_list.append(url)

        except Exception as e:
            self._log.emit(str(e) + '----' + str(e.__traceback__.tb_lineno) + '行')


    def get_url(self):
        url=''
        try:
            if self.stop_flag == 1:
                self.url_Queue.queue.clear()
                self._log.emit('停止扫描')
                return
            url = self.url_Queue.get()  # 从队列中取出
            request = requests.get(url, verify=False, timeout=self.timeout)
            httpStatusCode = request.status_code
            if httpStatusCode in [200, 403, 404, 500, 501, 502, 401, 210, 400]:
                self.url_list.append(url)
            else:
                self._log.emit("%s-不存活" % url)
        except:
            self._log.emit("%s-不存活" % url)