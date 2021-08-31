#!/usr/bin/env python
# -*- coding: utf-8 -*-
import queue
import re
import threading  # 导入线程相关模块
from socket import *
from urllib import parse

from Modules.Chrome_Screen import Chrome_Screen

import eventlet
import requests

requests.packages.urllib3.disable_warnings()
from PyQt5.QtCore import QThread, pyqtSignal

class Get_Title(QThread):
    _data = pyqtSignal(dict)  # 信号类型 str  更新table
    _num = pyqtSignal(int)  # 信号类型 str  更新进度条
    _count = pyqtSignal(int)  # 信号类型 str  更新进度条总数
    _log = pyqtSignal(str)  # 信号类型 str 更新日志
    def __init__(self,logger,url_text,threads, timeout,checkBox_302,chrome_driver,parent=None):
        super(Get_Title,self).__init__(parent)
        self.logger =logger
        self.gettitle_Queue = queue.Queue()
        self.url_list = url_text
        self.threads =threads
        self.timeout=timeout
        self.stop_flag =0
        self.checkBox_302 =checkBox_302
        self.chrome_driver =chrome_driver

        self.threads_list=[]
    def run(self):
        try:
            all_url_list = self.url_list.splitlines()
            self.url_list=[]
            all_url_list = list(filter(None, all_url_list))  # 去除 none 和 空字符
            for i in all_url_list:
                if "http://" not in i and "https://" not in i:
                    self.url_list.append("http://"+i)
                else:
                    self.url_list.append(i)
            try:
                self.gettitle_Queue.queue.clear()
                for url in self.url_list :
                    if self.stop_flag == 1:
                        self.gettitle_Queue.queue.clear()
                        self._log.emit('停止扫描')
                        return
                    else:
                        self.gettitle_Queue.put(url)
            except Exception as e:
                self._log.emit(str(e))
                pass
            if self.gettitle_Queue.qsize() > 0:
                self.scan()
            else:
                self._log.emit('NO URL')
                self._log.emit('停止扫描')
                return


        except Exception as e:
            pass
            # self.logger.error(str(e) + '----' + str(e.__traceback__.tb_lineno) + '行')



    def scan(self):
        try:
            if self.threads > self.gettitle_Queue.qsize():
                self.threads = self.gettitle_Queue.qsize()
            self._count.emit(len(self.url_list))
            self._log.emit(
                'URL数量:%s,线程:%s,超时:%s' % (len(self.url_list), str(self.threads), str(self.timeout)))
            self._log.emit("扫描开始")
            for i in range(self.threads):
                i = threading.Thread(target=self.TitleScanner, args=())
                self.threads_list.append(i)
            for t in self.threads_list:  # 启动线程
                t.start()
            for t in self.threads_list:  # 阻塞线程，等待线程结束
                t.join()
            self._data.emit({"end":True})  # 计算结果完成后，发送结果
            self._log.emit('扫描结束')
        except Exception as e:
            # pass
            self.logger.error(str(e) + '----' + str(e.__traceback__.tb_lineno) + '行')


    def TitleScanner(self):
        while True:
            try:
                if self.stop_flag==1:
                    return
                else:
                    Banner=''
                    title=''
                    Server = ''
                    ip=''
                    screen_img=''
                    eventlet.monkey_patch(thread=False, time=True)
                    with eventlet.Timeout(self.timeout+2, False):
                        if self.gettitle_Queue.empty():  # 队列空就结束
                            break
                        url = self.gettitle_Queue.get()  # 从队列中取出
                        self._num.emit((1))  # 计算结果完成后，发送结果
                        # print(host,port)
                        try:
                            try:
                                domain =  str(parse.urlparse(url).hostname)
                                # print(domain)
                                ip_list = gethostbyname(domain)
                                ip = str(ip_list)
                            except:
                                pass
                            try:
                                html = requests.get(url,verify = False,timeout=self.timeout,allow_redirects=self.checkBox_302)
                                if not html:
                                    html = requests.post(url,verify = False,timeout=self.timeout,allow_redirects=self.checkBox_302)
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
                                if html.headers.get('Server'):
                                    Server = html.headers.get('Server')
                                if html.headers.get('X-Powered-By'):
                                    Server =Server+"|"+ html.headers.get('X-Powered-By')
                                if self.chrome_driver:
                                    screen_img = Chrome_Screen(self.chrome_driver, url).main()

                            except Exception as e:
                                pass
                                # self.logger.error(str(e) + '----' + str(e.__traceback__.tb_lineno) + '行')
                            self.out_result(url,ip,title,Server,Banner,screen_img)
                        except Exception as e:
                            pass
                            # self.logger.error(str(e) + '----' + str(e.__traceback__.tb_lineno) + '行')
                            continue
                    continue
            except Exception as e:
                pass
                # self.logger.error(str(e) + '----' + str(e.__traceback__.tb_lineno) + '行')
                continue

    def out_result(self,url,ip,title,Server,Banner,screen_img=''):
        try:
            data= {"Url":url,"Ip":ip,"Title":title,"Server":Server,"Banner":Banner,"screen_img":screen_img}
            self._data.emit((data))  # 计算结果完成后，发送结果
        except Exception as e:
            self.logger.error(str(e) + '----' + str(e.__traceback__.tb_lineno) + '行')


        