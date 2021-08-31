import eventlet
import importlib
import queue
import socket
import sys


import threading
import time

sys.path.append('./Modules')
from Modules.Chrome_Screen import Chrome_Screen
import BaseInfo
from PyQt5.QtCore import QThread, pyqtSignal

class Domain_Start(QThread):
    """该线程用于计算耗时的累加操作"""
    _sum = pyqtSignal(dict)  # 信号类型 str
    def __init__(self,MainWindows,domain_plugins_dir,target,poc_data,heads_dict,threadnum,timeout,get_ip,get_title,logger,chrome_driver):
        super().__init__()
        self.stop_flag = 0
        self.MainWindows =MainWindows
        self.domain_Queue = queue.Queue()
        self.domain_plugins_dir = domain_plugins_dir
        self.poc_data = poc_data
        self.target = target
        self.heads_dict = heads_dict
        self.threadnum = threadnum
        self.timeout =timeout
        self.get_ip =get_ip
        self.get_title =get_title
        self.logger = logger
        self.chrome_driver =chrome_driver

    def run(self):
        #添加队列
        num= len(self.target)
        for u in self.target:
            for xuanzhong_data in self.poc_data:
                # print(xuanzhong_data)
                filename =self.domain_plugins_dir+'/' + xuanzhong_data['plugins_file']
                self.domain_Queue.put(u + '$$$' + filename + '$$$'+xuanzhong_data['plugins_name']+ '$$$'+xuanzhong_data['plugins_key1']+ '$$$'+xuanzhong_data['plugins_key2']+ '$$$'+xuanzhong_data['plugins_key3'])
        if self.threadnum >  self.domain_Queue.qsize():
            self.threadnum =  self.domain_Queue.qsize()
        if num==0:
            self.MainWindows.Ui.textEdit_doamin_log.append(
                "[%s]End:扫描结束。" % (time.strftime('%H:%M:%S', time.localtime(time.time()))))
            return
        else:
            self.MainWindows.Ui.textEdit_doamin_log.append(
                "[%s]Start:扫描开始..." % (time.strftime('%H:%M:%S', time.localtime(time.time()))))
            self.MainWindows.Ui.textEdit_doamin_log.append(
                "[%s]Success:共加载%s个域名，%s个插件..." % (time.strftime('%H:%M:%S', time.localtime(time.time())),len(self.target),len(self.poc_data)))
            self.MainWindows.Ui.pushButton_doamin_file.setEnabled(False)
            self.MainWindows.Ui.pushButton_doamin_start.setEnabled(False)
            threads=[]
            for i in range(self.threadnum):
                thread = threading.Thread(target=self.domain_scan, args=())
                thread.setDaemon(True)  # 设置为后台线程，这里默认是False，设置为True之后则主线程不用等待子线程
                threads.append(thread)
                thread.start()
            self.threadnum = len(threads)
    def domain_scan(self):
        while 1:
            try:
                if  self.domain_Queue.empty() or self.stop_flag:  # 队列空就结束
                    time.sleep(int(self.timeout))
                    self.MainWindows.Ui.pushButton_doamin_file.setEnabled(True)
                    self.MainWindows.Ui.pushButton_doamin_start.setEnabled(True)
                    self.MainWindows.Ui.pushButton_doamin_stop.setEnabled(False)
                    self.MainWindows.Ui.textEdit_doamin_log.append(
                        "<p style=\"color:green\">[%s]END:扫描结束！</p>" % (
                            (time.strftime('%H:%M:%S', time.localtime(time.time())))))
                    return
                #u + '$$$' + filename + '$$$' + xuanzhong_data['plugins_name'])
                all =  self.domain_Queue.get().split('$$$')  # 从队列中取出 #0
                domain = all[0]
                filename = all[1]
                plugins_name = all[2]
                key1 = all[3]
                key2 = all[4]
                key3 = all[5]
                try:
                    eventlet.monkey_patch(thread=False, time=True)
                    with eventlet.Timeout(600, False):
                        self.logger.info("Domain:" + domain + " " + filename)
                        nnnnnnnnnnnn1 = importlib.machinery.SourceFileLoader(filename[:-3], filename).load_module()
                        result = nnnnnnnnnnnn1.do_start(self,domain,key1,key2,key3,self.heads_dict,self.timeout)
                        if result=="END":
                            self.MainWindows.Ui.textEdit_doamin_log.append(
                            "<p style=\"color:green\">[%s]END:%s--%s 运行结束！</p>" % (
                                (time.strftime('%H:%M:%S', time.localtime(time.time()))),domain, plugins_name))
                        else:
                            self.MainWindows.Ui.textEdit_doamin_log.append(
                            "<p style=\"color:red\">[%s]END:%s--%s 异常结束，未获取到END！</p>" % (
                                (time.strftime('%H:%M:%S', time.localtime(time.time()))),domain, plugins_name))
                        # 存在
                        continue
                    self.MainWindows.Ui.textEdit_doamin_log.append(
                        "<p style=\"color:red\">[%s]Error:%s脚本运行超时！</p>" % (
                            (time.strftime('%H:%M:%S', time.localtime(time.time()))), filename))
                    continue
                except Exception as  e:
                    self.logger.error(str(e) + '----' + str(e.__traceback__.tb_lineno) + '行')
                    self.MainWindows.Ui.textEdit_doamin_log.append(
                        "<p style=\"color:red\">[%s]Error:%s----%s----%s。</p>" % (
                            (time.strftime('%H:%M:%S', time.localtime(time.time()))), domain, plugins_name, '脚本运行超时'))
                    continue

            except Exception as  e:
                self.logger.error(str(e) + '----' + str(e.__traceback__.tb_lineno) + '行')
                self.MainWindows.Ui.textEdit_doamin_log.append(
                    "<p style=\"color:red\">[%s]Error:%s----%s----%s。</p>" % (
                        (time.strftime('%H:%M:%S', time.localtime(time.time()))), domain, plugins_name, '脚本运行超时'))
                continue

    def result_echo(self,result):
        if not result.get("subdomain_ip") and result.get("subdomain") and self.get_ip:
            result['subdomain_ip'] = self.getIP(result.get("subdomain"))
        if not result.get("subdomain_title") and result.get("subdomain") and self.get_title:
            result['subdomain_title'] = self.gettitle('http://'+result.get("subdomain"))
        if self.chrome_driver:
            try:
                # print(result.get("subdomain"))
                url = result.get("subdomain")
                if url :
                    if 'http://' not in url.lower() and 'https://' not in url.lower():
                        url = 'http://'+url
                    if self.chrome_driver:
                        result['screen_img']=Chrome_Screen(self.chrome_driver,url).main()
            except:
                pass
        self._sum.emit(result)

    def getIP(self,domain):
        myaddr = socket.getaddrinfo(domain, 'http')
        return(myaddr[0][4][0])

    def gettitle(self, domain):
        responce = BaseInfo.http_info(domain)
        if responce.get('title'):
            return(responce.get('title'))
        else:
            responce = BaseInfo.http_info(domain)
            return (responce.get('title'))