#!/usr/bin/python
# -*- coding: UTF-8 -*-
import base64
import configparser
import datetime
import importlib


import mmh3, codecs
import os
import socket
import sys
import threading
import traceback
import webbrowser

from PyQt5.QtWebEngineWidgets import *

sys.path.append('./Modules')
sys.path.append('./Gui')

if hasattr(sys, 'frozen'):
    os.environ['PATH'] = sys._MEIPASS + ";" + os.environ['PATH']
from PyQt5 import QtWidgets, QtCore, QtGui
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from PyQt5.QtGui import *
import csv, re, requests, time, sqlite3
from Gui.main import Ui_MainWindow
from Gui.Vuln_Plugins import Ui_Form_Vuln
from Gui.Domain_Plugins import Ui_Form_Domain
from Gui.Vuln_Info import Ui_From_Vuln_Info
from Gui.TableWidget import Ui_TableWidget
from Gui.Vuln_Edit import Ui_Form_Vuln_Edit


import pyperclip
import frozen_dir
from Modules.Vuln_Scanner import Vuln_Scanner
from Modules.Vuln_Exp import Vuln_Exp
from Modules.Domain_Start import Domain_Start
from Modules.Encode_Encrypt import Encode_Encrypt
from Modules.Port_Scan import Port_Scan
from Modules.Get_Title import Get_Title
from Modules.Tools_Start import Tools_Start
from Modules.Passwd_Brute import Passwd_Brute
from Modules.Fofa_Start import Fofa_Start
from Modules.Fingerprint_Start import Fingerprint_Start
from Modules.PythonHighlighter import PythonHighlighter



import logging
SETUP_DIR = frozen_dir.app_path()
sys.path.append(SETUP_DIR)
DB_NAME = './Conf/DB.db'
version = '1.0.0'
vuln_plugins_dir = './Plugins/Vuln_Plugins/'
domain_plugins_dir = './Plugins/Domain_Plugins/'
portscan_plugins_dir = './Plugins/Port_Scan/'
dirscan_plugins_dir = './Plugins/Dir_Scan/'
exp_plugins_dir = './Plugins/Exp_Plugins/'
log_file_dir ='./Logs/'
config_file_dir = './Conf/config.ini'
vuln_plugins_template = './Plugins/Plugins_Template/Plugins_漏洞插件模板.py'
update_time = '20210831 无限BUG版'
requests.packages.urllib3.disable_warnings()

class MainWindows(QtWidgets.QMainWindow, Ui_MainWindow):  # 主窗口
    def __init__(self, parent=None):
        sys.excepthook = self.HandleException
        super(MainWindows, self).__init__(parent)
        # self.setWindowFlags(Qt.FramelessWindowHint | Qt.WindowStaysOnTopHint) #去掉标题栏
        self.Ui = Ui_MainWindow()
        self.Ui.setupUi(self)
        self.setWindowTitle('Emperor  by qianxiao996 v' + version + ' ' + update_time)
        self.setWindowIcon(QtGui.QIcon('Conf/main.png'))
        # self.setFixedSize(self.width(), self.height())  # 设置宽高不可变
        # self.Ui.exit.clicked.connect(QtCore.QCoreApplication.instance().quit)  #退出
        # self.check_update()
        # self.setWindowOpacity(0.8)  #窗口透明度

        # 存放poc插件
        self.poc_cms_name_dict = {}
        # 存放exp插件
        self.exp_cms_name_dict = {}
        # 存放domain插件
        self.domain_dict = {}
        # self.Ui.browser1.load(QUrl("https://qianxiao996.cn"))
        # self.Ui.dir_browser.load(QUrl("https://qianxiao996.cn"))
        # self.Ui.browser1_domain.load(QUrl("https://qianxiao996.cn"))
        #安全知识库
        self.Ui.action_zhishiku.triggered.connect(lambda:self.alert_web("https://vuln.online"))  # 查看插件
        # self.Ui.browser1.setHtml('''<!DOCTYPE html>
        # <html>
        # <head>
        #     <meta charset="utf-8">
        #     <meta http-equiv="X-UA-Compatible" content="IE=edge">
        #     <title></title>
        #     <link rel="stylesheet" href="">
        # </head>
        # <body>
        #     <div>测试html</div>
        # </body>
        # </html>''')
        self.__Logger = self.__BuildLogger()

        # 存放开始扫描的漏洞url
        self.vuln_url_list = []
        # 存放子域名扫描的主域名
        self.domain_url_list = []
        # 初始化加载插件
        self.load_config()
        self.load_vuln_plugins()
        self.load_domain_plugins()
        self.load_exp_plugins()
        self.load_options_menu()
        self.load_portscan_plugins()
        self.load_fofa_plugins()
        self.load_note_plugins()
        self.Ui.tabWidget_fofa.tabCloseRequested.connect(self.closeTab)
        self.Ui.lineEdit_passwd_brute_ip.setText(socket.gethostbyname(socket.gethostname()) + '/24')


        # 漏洞扫描
        self.Ui.pushButton_vuln_file.clicked.connect(lambda:self.vuln_import_file(self.Ui.lineEdit_vuln_url,self.Ui.textEdit_log,'vuln_scanner'))  # 导入地址
        self.Ui.pushButton_vuln_start.clicked.connect(self.vuln_Start)  # 开始扫描
        self.Ui.pushButton_vuln_stop.clicked.connect(self.vuln_Stop)  # 停止扫描
        self.Ui.pushButton_vuln_expstart.clicked.connect(self.vuln_exp)  # 一键利用
        self.Ui.pushButton_vuln_all.clicked.connect(self.vuln_all)  # 全选
        self.Ui.pushButton_vuln_noall.clicked.connect(self.vuln_noall)  # 反选

        # 插件管理（漏洞）
        self.Ui.action_vuln_reload.triggered.connect(self.vuln_reload_Plugins)  # 重新加载插件
        self.Ui.action_vuln_showplubins.triggered.connect(self.vuln_ShowPlugins)  # 查看插件

        # 选项
        self.Ui.action_about_start.triggered.connect(self.about)  # 关于
        self.Ui.action_update_start.triggered.connect(self.version_update)  # 更新
        self.Ui.action_ideas_start.triggered.connect(self.ideas)  # 意见反馈

        # 漏洞利用
        self.Ui.vuln_exp_button_cmd.clicked.connect(lambda: self.exp_send('cmd'))
        self.Ui.vuln_exp_button_shell.clicked.connect(lambda: self.exp_send('shell'))
        self.Ui.vuln_exp_button_uploadfile.clicked.connect(lambda: self.exp_send('uploadfile'))
        self.Ui.vuln_type.activated[str].connect(self.change_exp_list)
        self.Ui.vuln_name.activated[str].connect(self.change_exp_name_change)
        self.Ui.vuln_exp_comboBox_shell.activated[str].connect(self.change_exp_combox)
        self.Ui.vuln_exp_button_getfile.clicked.connect(lambda: self.import_file(self.Ui.vuln_exp_textEdit_shell,'',self.Ui.vuln_exp_lineEdit_filename))  # 导入地址

        #
        # 漏洞扫描右键菜单
        self.Ui.tableWidget_vuln.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.Ui.tableWidget_vuln.customContextMenuRequested.connect(self.createtableWidget_vulnMenu)#将菜单的信号链接到自定义菜单槽函数
        # self.Ui.tableWidget_vuln.customContextMenuRequested['QPoint'].connect(self.createtableWidget_vulnMenu)

        # 端口扫描右键菜单
        self.Ui.portscan_result.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.Ui.portscan_result.customContextMenuRequested.connect(self.createtableWidget_portscan_vulnMenu)

        # 子域名扫描右键菜单
        self.Ui.tableWidget_domain.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.Ui.tableWidget_domain.customContextMenuRequested.connect(self.createtableWidget_domain_vulnMenu)



        # 插件管理（子域名）
        self.Ui.action_domain_reload.triggered.connect(self.domain_reload_Plugins)  # 重新加载插件
        self.Ui.pushButton_doamin_all.clicked.connect(self.domain_all)  # 全选
        self.Ui.pushButton_doamin_noall.clicked.connect(self.domain_noall)  # 反选
        self.Ui.action_domain_showplubins.triggered.connect(self.domain_ShowPlugins)  # 查看插件
        self.Ui.tableWidget_domain.doubleClicked.connect(lambda:self.alert_web(self.Ui.tableWidget_domain.selectedItems()[1].text()))
        self.Ui.tableWidget_domain.clicked.connect(self.change_domain_data)
        # 子域名扫描
        self.Ui.pushButton_doamin_file.clicked.connect(lambda :self.vuln_import_file(self.Ui.lineEdit_doamin_url,self.Ui.textEdit_doamin_log,'domain_scanner'))  # 导入地址
        self.Ui.pushButton_doamin_start.clicked.connect(self.domain_Start)  # 开始扫描
        self.Ui.pushButton_doamin_stop.clicked.connect(self.domain_Stop)  # 停止扫描

        # 端口扫描
        self.Ui.portscan_port_file.activated[str].connect(self.change_portscan_combox)
        self.Ui.portscan_result.clicked.connect(self.change_portscan_data)
        self.Ui.portscan_result.doubleClicked.connect(self.alert_portscan)
        self.Ui.portscan_start.clicked.connect(self.portscan_Start)  # 开始扫描
        self.Ui.portscan_stop.clicked.connect(self.portscan_Stop)  # 停止扫描
        self.Ui.portscan_add.clicked.connect(self.portscan_add)  # 添加扫描
        self.portscan_R = threading.Lock()


        # 编码解码模块        # encode
        self.Ui.encode_encode.clicked.connect(
            lambda: self.encode_encrypt('encode', self.Ui.comboBox_encode.currentText()))
        self.Ui.encode_decode.clicked.connect(
            lambda: self.encode_encrypt('decode', self.Ui.comboBox_encode.currentText()))
        self.Ui.encode_encrypt.clicked.connect(
            lambda: self.encode_encrypt('encrypt', self.Ui.comboBox_encrypt.currentText()))
        self.Ui.encode_decrypt.clicked.connect(
            lambda: self.encode_encrypt('decrypt', self.Ui.comboBox_encrypt.currentText()))
        # copy按钮  替换按钮  cleaer按钮在ui中
        self.Ui.encode_copy_source.clicked.connect(
            lambda: self.Copy_text(self.Ui.encode_Source_text.toPlainText()))  # copy_source
        self.Ui.encode_copy_result.clicked.connect(
            lambda: self.Copy_text(self.Ui.encode_Result_text.toPlainText()))  # copy_result
        self.Ui.encode_tihuan_button.clicked.connect(self.replace_text)  # replace_result

        # 进制转换
        self.Ui.encode_2_8.clicked.connect(lambda: self.encode_encrypt("binary", self.Ui.encode_2_8.text()))
        self.Ui.encode_2_10.clicked.connect(lambda: self.encode_encrypt("binary", self.Ui.encode_2_10.text()))
        self.Ui.encode_2_16.clicked.connect(lambda: self.encode_encrypt("binary", self.Ui.encode_2_16.text()))
        self.Ui.encode_8_2.clicked.connect(lambda: self.encode_encrypt("binary", self.Ui.encode_8_2.text()))
        self.Ui.encode_8_10.clicked.connect(lambda: self.encode_encrypt("binary", self.Ui.encode_8_10.text()))
        self.Ui.encode_8_16.clicked.connect(lambda: self.encode_encrypt("binary", self.Ui.encode_8_16.text()))
        self.Ui.encode_10_2.clicked.connect(lambda: self.encode_encrypt("binary", self.Ui.encode_10_2.text()))
        self.Ui.encode_10_8.clicked.connect(lambda: self.encode_encrypt("binary", self.Ui.encode_10_8.text()))
        self.Ui.encode_10_16.clicked.connect(lambda: self.encode_encrypt("binary", self.Ui.encode_10_16.text()))
        self.Ui.encode_16_2.clicked.connect(lambda: self.encode_encrypt("binary", self.Ui.encode_16_2.text()))
        self.Ui.encode_16_8.clicked.connect(lambda: self.encode_encrypt("binary", self.Ui.encode_16_8.text()))
        self.Ui.encode_16_10.clicked.connect(lambda: self.encode_encrypt("binary", self.Ui.encode_16_10.text()))
        self.Ui.encode_all.clicked.connect(lambda: self.encode_encrypt("binary", self.Ui.encode_all.text()))

        #get title
        self.appand_gettitle_data = []
        self.Ui.pushButton_gettitle_start.clicked.connect(self.get_title_start)
        self.Ui.pushButton_gettitle_stop.clicked.connect(self.get_title_stop)
        self.Ui.pushButton_gettitle_daochu.clicked.connect(lambda: self.export_file(self.Ui.tableWidget_gettitle_result, self.Ui.plainTextEdit_gettitle_log))
        self.Ui.pushButton_gettitle_clear.clicked.connect(lambda: self.Clear_tableWidget(self.Ui.tableWidget_gettitle_result))
        self.Ui.tableWidget_gettitle_result.clicked.connect(self.change_gettitle_data)
        # self.gettitle_lock = threading.Lock()


        #默认设备密码
        self.load_morepasswd()
        self.Ui.listWidget_morenpasswd_list.clicked.connect(self.change_morenpasswd_click_value)
        self.Ui.pushButton_morenpasswd_username_copy.clicked.connect(lambda :self.Copy_text(self.Ui.textEdit_morenpasswd_username.toPlainText()))
        self.Ui.pushButton_pushButton_morenpasswd_passwd_copy.clicked.connect(lambda :self.Copy_text(self.Ui.textEdit_morenpasswd_passwd.toPlainText()))
        self.Ui.pushButton_morenpasswd_daochu.clicked.connect(lambda: self.export_file(self.Ui.tableWidget_morenpasswd_result, ''))
        self.Ui.pushButton_morenpasswd_start.clicked.connect(self.morenpasswd_start)
        #杀软查询
        self.Ui.pushButton_sharuanchaxun_start.clicked.connect(self.sharuanchaxun_start)

        #目录扫描
        self.load_dir_plugins()
        self.Ui.pushButton_dir_checkall.clicked.connect(self.dir_check_all)
        self.Ui.pushButton_dir_checkno.clicked.connect(self.dir_check_no)

        #指纹识别
        self.Ui.pushButton_fingerprint_start.clicked.connect(self.fingerprint_start)
        self.Ui.pushButton_fingerprint_exit.clicked.connect(self.fingerprint_stop)
        self.Ui.pushButton_fingerprint_delete.clicked.connect(lambda: self.Delete_tableWidget(self.Ui.tableWidget_fingerprint_result))
        self.Ui.pushButton_fingerprint_clear.clicked.connect(lambda: self.Clear_tableWidget(self.Ui.tableWidget_fingerprint_result))




        #密码破解
        self.Ui.checkBox_passwd_brute_moren_dict.stateChanged.connect(self.change_passwd_brute_dict)
        self.Ui.pushButton_passwd_brute_daochu.clicked.connect(lambda: self.export_file(self.Ui.tableWidget_passwd_brute_result, self.Ui.textEdit_passwd_brute_logs))
        self.Ui.pushButton_passwd_brute_setting.clicked.connect( self.passwd_brute_setting)
        self.Ui.pushButton_passwd_brute_username.clicked.connect(lambda: self.Ui.lineEdit_passwd_brute_username.setText(self.file_open(r"All files(*.*)")))  # 导入地址
        self.Ui.pushButton_passwd_brute_ip.clicked.connect(lambda: self.Ui.lineEdit_passwd_brute_ip.setText(self.file_open(r"All files(*.*)")))  # 导入地址
        self.Ui.pushButton_passwd_brute_passwd.clicked.connect(lambda: self.Ui.lineEdit_passwd_brute_passwd.setText(self.file_open(r"All files(*.*)")))  # 导入地址
        self.Ui.pushButton_passwd_brute_start.clicked.connect( self.passwd_brute_start)
        self.Ui.pushButton_passwd_brute_stop.clicked.connect( self.passwd_brute_stop)
        self.Ui.pushButton_passwd_brute_clear.clicked.connect(lambda: self.Clear_tableWidget(self.Ui.tableWidget_passwd_brute_result))



        #小工具
        self.Ui.tools_ip.clicked.connect(lambda :self.tools("ipsearch"))
        self.Ui.tool_daxie.clicked.connect(lambda :self.tools("alldaxie"))
        self.Ui.tools_xiaoxie.clicked.connect(lambda :self.tools("allxiaoxie"))
        self.Ui.tools_daoxu.clicked.connect(lambda :self.tools("daoxu"))
        self.Ui.tools_zhongwen_pinyin.clicked.connect(lambda :self.tools("zhongwen_pinyin"))
        self.Ui.tools_tiqushouzimu.clicked.connect(lambda :self.tools("tiqushouzimu"))

        self.Ui.tools_remove_duplicate.clicked.connect(lambda :self.tools("remove_duplicate"))
        self.Ui.tools_get_ip.clicked.connect(lambda :self.tools("get_ip"))
        self.Ui.tools_get_china_ip.clicked.connect(lambda :self.tools("get_china_ip"))
        self.Ui.tools_remove_china_ip.clicked.connect(lambda :self.tools("remove_china_ip"))



        #采集收集
        self.zoomeye_access_token=''
        self.Ui.fofa_config.clicked.connect(self.fofa_setting)
        self.Ui.fofa_go.clicked.connect(self.fofa_go)
        self.Ui.fofa_icon.clicked.connect(self.fofa_get_icon)
        self.highlighter = PythonHighlighter(self.Ui.vuln_exp_textEdit_shell.document())


        #渗透笔记
        self.Ui.pushButton_note_save.clicked.connect(self.save_note_info)
        self.Ui.pushButton_note_delete.clicked.connect(self.delete_note_info)



    ## @detail 创建logger类
    def __BuildLogger(self):
        logger = logging.getLogger(__file__)
        logger.setLevel(logging.DEBUG)
        # 建立一个filehandler来把日志记录在文件里，级别为debug以上
        fh = logging.FileHandler(log_file_dir + "FrameScan.log")
        fh.setLevel(logging.DEBUG)
        # 建立一个streamhandler来把日志打在CMD窗口上，级别为error以上
        ch = logging.StreamHandler()
        ch.setLevel(logging.DEBUG)
        # 设置日志格式
        formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(lineno)s %(message)s",
                                      datefmt="%Y-%m-%d %H:%M:%S")
        ch.setFormatter(formatter)
        fh.setFormatter(formatter)
        # 将相应的handler添加在logger对象中
        logger.addHandler(ch)
        logger.addHandler(fh)
        # 开始打日志
        # logger.debug("debug message")
        # logger.info("info message")
        # logger.warning("warn message")
        # logger.error("error message")
        # logger.critical("critical message")
        return logger
    def load_morepasswd(self):
        sql_poc = "SELECT distinct type from passwd where type !=''"
        passwd_type_list = self.sql_search(sql_poc)
        # print(passwd_type_list)
        for type in passwd_type_list:
            self.Ui.listWidget_morenpasswd_list.addItem(str(type[0].strip()))
    def encode_encrypt(self, type, encode_type):
        text = self.Ui.encode_Source_text.toPlainText()
        encode2 = Encode_Encrypt(self, type, encode_type, text)
        encode2.start()  # 线程启动

    def replace_text(self):
        type = self.Ui.encode_replace_type.currentText()
        source_text = self.Ui.encode_tihuan_Source.text()
        result_text = self.Ui.encode_tihuan_Result.text()
        if type == "Source":
            data = self.Ui.encode_Source_text.toPlainText()
            text = data.replace(source_text, result_text)
            self.Ui.encode_Source_text.setText(str(text))
        elif type == "Result":
            data = self.Ui.encode_Result_text.toPlainText()
            text = data.replace(source_text, result_text)
            self.Ui.encode_Result_text.setText(str(text))
        else:
            pass

    def Copy_text(self, data):
            # 访问剪切板，存入值
        pyperclip.copy(data)
        # wincld.OpenClipboard()
        # wincld.EmptyClipboard()
        # wincld.SetClipboardData(win32con.CF_UNICODETEXT, data)
        # wincld.CloseClipboard()

    def load_options_menu(self):
        # #选项
        othersmenubar = self.menuBar()  # 获取窗体的菜单栏
        others = othersmenubar.addMenu("选项")
        for i in ["关于软件", '检查更新', '意见反馈']:
            sub_action = QAction(QIcon(''), i, self)
            others.addAction(sub_action)
        impMenu = QMenu("皮肤风格", self)
        # print(type(config_setup))
        for z in config_setup.options('QSS_List'):
            sub_action = QAction(QIcon(''), z, self)
            # 开启多选框
            sub_action.setCheckable(True)
            impMenu.addAction(sub_action)
        others.addMenu(impMenu)
        others.triggered[QAction].connect(self.show_others)
        # 初始化修改风格
        for key, value in config_setup.items('QSS_List'):
            if value == config_setup.get('QSS_Setup', 'QSS'):
                self.change_pifu(key)
                return
        QMessageBox.critical(self, 'QSS错误', "当前加载的QSS文件不在菜单选项中！")
    def load_portscan_plugins(self):
        for root, dirs, files in os.walk(portscan_plugins_dir):
            for file in files:
                if file[-4:] == ".ini":
                    self.Ui.portscan_port_file.addItem(file)
        self.change_portscan_combox()
        self.Ui.portscan_ip.setText(socket.gethostbyname(socket.gethostname())+'/24')
    def load_fofa_plugins(self):
        type_sql = "SELECT distinct  name from vuln_collect where name !='' and type ='tree'  order by id"
        type_data = self.sql_search(type_sql)
        sql = "SELECT * from vuln_collect where type ='tree' order by id"
        data = self.sql_search(sql, 'dict')
        for root_name in type_data:
            self.Ui.fofa_type.addItem( root_name[0])
            root = QTreeWidgetItem(self.Ui.treeWidget_fofa)
            root.setText(0, root_name[0])  # 设置根节点的名称
            root.setFlags(QtCore.Qt.ItemIsSelectable|QtCore.Qt.ItemIsDragEnabled|QtCore.Qt.ItemIsDropEnabled|QtCore.Qt.ItemIsUserCheckable|QtCore.Qt.ItemIsEnabled|QtCore.Qt.ItemIsTristate)
            for cms_single in data:
                # 为root节点设置子结点
                if cms_single.get("name") ==root_name[0]:
                    value_list = cms_single.get("value").split("|")
                    for child_value in value_list:
                        child_value = child_value.split(":")
                        child1 = QTreeWidgetItem(root)
                        if len(child_value)==2 and child_value[1]=='1':
                            child1.setCheckState(0, QtCore.Qt.Checked)
                        else:
                            child1.setCheckState(0, QtCore.Qt.Unchecked)
                        child1.setText(0,child_value[0] )
        sql = "select * from vuln_collect where type='help'"
        help_data =  self.sql_search(sql,'dict')
        self.fofa_tab_addpage_help(help_data)
    def change_portscan_combox(self):
        vuln_name_text = self.Ui.portscan_port_file.currentText()
        f = open(portscan_plugins_dir + '/' + vuln_name_text, 'r',encoding='utf-8')
        data = f.read()
        f.close()
        self.Ui.portscan_port_list.setText(data)
    def change_exp_combox(self):
        exp_name_text = self.Ui.vuln_exp_comboBox_shell.currentText()
        f = open(exp_plugins_dir + '/' + exp_name_text, 'r',encoding='utf-8')
        data = f.read()
        f.close()
        self.Ui.vuln_exp_textEdit_shell.setPlainText(data)
        self.Ui.vuln_exp_lineEdit_filename.setText(exp_name_text)
    def change_portscan_data(self):
    #端口扫描点击行显示数据包及预览
        try:
            imgsrc = self.Ui.portscan_result.selectedItems()[-1].text()
            # imgsrc = ""
            if imgsrc:
                qrPixmap = QPixmap(QImage.fromData(base64.b64decode(imgsrc))).scaled(self.Ui.portscan_img.width(), self.Ui.portscan_img.height())
                self.Ui.portscan_img.setPixmap(qrPixmap)
            else:
                self.Ui.portscan_img.setText("没有截图")
        except:
            self.Ui.portscan_img.setText("截图加载失败")
        if len(self.Ui.portscan_result.selectedItems())>5:
            banner = self.Ui.portscan_result.selectedItems()[5].text()
            self.Ui.portscan_banner.setPlainText(banner)
            # self.Ui.portscan_result_text.setHtml(banner)
        # if self.Ui.portscan_result.selectedItems()[2].text() in ["HTTP", "HTTPS", "http", "https"]:
        #     url = self.Ui.portscan_result.selectedItems()[2].text().lower() + "://" + \
        #           self.Ui.portscan_result.selectedItems()[0].text() + ":" + self.Ui.portscan_result.selectedItems()[
        #               1].text()
        # else:
        #     url = "http://" + \
        #           self.Ui.portscan_result.selectedItems()[0].text() + ":" + self.Ui.portscan_result.selectedItems()[
        #               1].text()
        #
        # self.Ui.browser1.load(QUrl(url))
    def change_domain_data(self):
        try:
            imgsrc = self.Ui.tableWidget_domain.selectedItems()[-1].text()
            # imgsrc = ""
            if imgsrc:
                qrPixmap = QPixmap(QImage.fromData(base64.b64decode(imgsrc))).scaled(self.Ui.browser1_domain.width(), self.Ui.browser1_domain.height())
                self.Ui.browser1_domain.setPixmap(qrPixmap)
            else:
                self.Ui.browser1_domain.setText("没有截图")
        except:
            self.Ui.browser1_domain.setText("截图加载失败")
        #端口扫描点击行显示数据包及预览
        # url =self.Ui.tableWidget_domain.selectedItems()[1].text()
        #     # self.Ui.portscan_result_text.setHtml(banner)
        # if ("http://" not in url) and ("https://" not in url):
        #     url = "http://"+url
        # self.Ui.browser1_domain.load(QUrl(url))
    def load_config(self):
        global config_setup
        global qss_style
        # 实例化configParser对象
        config_setup = configparser.ConfigParser()
        # -read读取ini文件
        config_setup.read(config_file_dir, encoding='utf-8')
        if 'QSS_Setup' not in config_setup:  # 如果分组type不存在则插入type分组
            config_setup.add_section('QSS_Setup')
            config_setup.set("QSS_Setup", "QSS", 'default.qss')
            config_setup.write(open(config_file_dir, "r+", encoding="utf-8"))  # r+模式
            qss_Setup = 'default.qss'
        else:
            qss_Setup = config_setup.get('QSS_Setup', 'QSS')
        with open("Qss/" + qss_Setup, 'r', encoding='utf-8') as f:
            qss_style = f.read()
            f.close()
        self.setStyleSheet(qss_style)

    def change_pifu(self, text):
        othersmenubar = self.menuBar()  # 获取窗体的菜单栏
        #
        # print(i[1].menu().actions()[4].text())
        for i in othersmenubar.actions():
                # print(i.text())
                if i.text() == "选项":
                    # sub_action = i()
                    for j in i.menu().actions():
                        # 输出为关于软件、检查更新、意见反馈、皮肤风格
                        if j.text() == "皮肤风格":
                            for k in j.menu().actions():
                                if k.text() == text:
                                    k.setChecked(True)
                                else:
                                    k.setChecked(False)
                            return
    def createtableWidget_vulnMenu(self):
        '''''
                创建右键菜单
        '''
        # 必须将ContextMenuPolicy设置为Qt.CustomContextMenu
        # 否则无法使用customContextMenuRequested信号
        self.Ui.tableWidget_vuln.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.Ui.tableWidget_vuln.customContextMenuRequested.connect(self.showContextMenu)
        # 创建QMenu
        self.contextMenu = QtWidgets.QMenu(self)
        self.open = self.contextMenu.addAction(u'打开')
        self.daochu = self.contextMenu.addAction(u'导出')
        self.second = self.contextMenu.addMenu(u'复制')
        self.copy_url = self.second.addAction(u'网页地址')
        self.copy_vuln_name = self.second.addAction(u'漏洞名称')
        self.copy_path = self.second.addAction(u'插件路径')
        self.copy_payload = self.second.addAction(u'返回信息')
        self.copy_all = self.second.addAction(u'全部')
        self.delete_textEdit = self.contextMenu.addAction(u'删除')
        self.clear_textEdit = self.contextMenu.addAction(u'清空')

        # 将动作与处理函数相关联
        # 这里为了简单，将所有action与同一个处理函数相关联，
        # 当然也可以将他们分别与不同函数关联，实现不同的功能
        self.open.triggered.connect(self.open_url)
        self.daochu.triggered.connect(lambda: self.export_file(self.Ui.tableWidget_vuln, self.Ui.textEdit_log))
        self.copy_url.triggered.connect(lambda: self.Copy_tableWidget(self.Ui.tableWidget_vuln,0))
        self.copy_vuln_name.triggered.connect(lambda: self.Copy_tableWidget(self.Ui.tableWidget_vuln,1))
        self.copy_path.triggered.connect(lambda: self.Copy_tableWidget(self.Ui.tableWidget_vuln,2))
        self.copy_payload.triggered.connect(lambda: self.Copy_tableWidget(self.Ui.tableWidget_vuln,4))
        self.copy_all.triggered.connect(lambda: self.Copy_tableWidget(self.Ui.tableWidget_vuln,'all'))
        self.clear_textEdit.triggered.connect(lambda: self.Clear_tableWidget(self.Ui.tableWidget_vuln))
        self.delete_textEdit.triggered.connect(lambda: self.Delete_tableWidget(self.Ui.tableWidget_vuln))

    # 右键点击时调用的函数，移动鼠标位置
    def showContextMenu(self, pos):
        # 菜单显示前，将它移动到鼠标点击的位置
        self.contextMenu.move(QtGui.QCursor.pos())
        self.contextMenu.show()
    def createtableWidget_portscan_vulnMenu(self):
        '''''
                创建右键菜单
        '''
        # 必须将ContextMenuPolicy设置为Qt.CustomContextMenu
        # 否则无法使用customContextMenuRequested信号
        self.Ui.portscan_result.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.Ui.portscan_result.customContextMenuRequested.connect(self.showContextMenu)
        # 创建QMenu
        self.contextMenu = QtWidgets.QMenu(self)
        self.open_address = self.contextMenu.addAction(u'打开地址')
        self.daochu_portscan = self.contextMenu.addAction(u'导出数据')
        self.copy_portscan = self.contextMenu.addMenu(u'复制内容')
        self.copy_portscan_url = self.copy_portscan.addAction(u'URL')
        self.copy_portscan_ip = self.copy_portscan.addAction(u'IP')
        self.copy_portscan_port = self.copy_portscan.addAction(u'端口')
        self.copy_portscan_title = self.copy_portscan.addAction(u'Title')
        self.copy_portscan_banner= self.copy_portscan.addAction(u'Banner')
        self.copy_portscan_all = self.copy_portscan.addAction(u'全部')
        self.delete_portscan_textEdit = self.contextMenu.addAction(u'删除此条')
        self.clear_portscan_textEdit = self.contextMenu.addAction(u'清空数据')

        # 将动作与处理函数相关联
        # 这里为了简单，将所有action与同一个处理函数相关联，
        # 当然也可以将他们分别与不同函数关联，实现不同的功能
        self.open_address.triggered.connect(lambda: self.open_domain_url('port_url'))
        self.daochu_portscan.triggered.connect(lambda: self.export_file(self.Ui.portscan_result, self.Ui.portscan_logs))
        self.copy_portscan_url.triggered.connect(lambda: self.Copy_portscan_url_tableWidget())
        self.copy_portscan_ip.triggered.connect(lambda: self.Copy_tableWidget(self.Ui.portscan_result,0))
        self.copy_portscan_port.triggered.connect(lambda: self.Copy_tableWidget(self.Ui.portscan_result,1))
        self.copy_portscan_title.triggered.connect(lambda: self.Copy_tableWidget(self.Ui.portscan_result,4))
        self.copy_portscan_banner.triggered.connect(lambda: self.Copy_tableWidget(self.Ui.portscan_result,5))
        self.copy_portscan_all.triggered.connect(lambda: self.Copy_tableWidget(self.Ui.portscan_result,'all'))
        self.delete_portscan_textEdit.triggered.connect(lambda: self.Delete_tableWidget(self.Ui.portscan_result))
        self.clear_portscan_textEdit.triggered.connect(lambda: self.Clear_tableWidget(self.Ui.portscan_result))

    # 子域名扫描右键菜单
    def createtableWidget_domain_vulnMenu(self):
        '''''
                创建右键菜单
        '''
        # 必须将ContextMenuPolicy设置为Qt.CustomContextMenu
        # 否则无法使用customContextMenuRequested信号
        self.Ui.tableWidget_domain.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.Ui.tableWidget_domain.customContextMenuRequested.connect(self.showContextMenu)
        # 创建QMenu
        self.contextMenu = QtWidgets.QMenu(self)
        self.open_subdomain = self.contextMenu.addAction(u'打开子域名')
        self.open_domain = self.contextMenu.addAction(u'打开主域名')
        self.daochu = self.contextMenu.addAction(u'导出数据')
        self.copy = self.contextMenu.addMenu(u'复制内容')
        self.copy_domain = self.copy.addAction(u'主域名')
        self.copy_subdomain = self.copy.addAction(u'子域名')
        self.copy_ip = self.copy.addAction(u'IP地址')
        self.copy_title = self.copy.addAction(u'网站标题')
        self.copy_all = self.copy.addAction(u'全部')
        self.delete_textEdit = self.contextMenu.addAction(u'删除此条')
        self.clear_textEdit = self.contextMenu.addAction(u'清空数据')

        # 将动作与处理函数相关联
        # 这里为了简单，将所有action与同一个处理函数相关联，
        # 当然也可以将他们分别与不同函数关联，实现不同的功能
        self.open_subdomain.triggered.connect(lambda: self.open_domain_url('subdomain'))
        self.open_domain.triggered.connect(lambda: self.open_domain_url('domain'))
        self.daochu.triggered.connect(
            lambda: self.export_file(self.Ui.tableWidget_domain, self.Ui.textEdit_doamin_log))
        self.copy_domain.triggered.connect(lambda: self.Copy_tableWidget(self.Ui.tableWidget_domain,0))
        self.copy_subdomain.triggered.connect(lambda: self.Copy_tableWidget(self.Ui.tableWidget_domain,1))
        self.copy_ip.triggered.connect(lambda: self.Copy_tableWidget(self.Ui.tableWidget_domain,2))
        self.copy_title.triggered.connect(lambda: self.Copy_tableWidget(self.Ui.tableWidget_domain,3))
        self.copy_all.triggered.connect(lambda: self.Copy_tableWidget(self.Ui.tableWidget_domain,'all'))
        self.delete_textEdit.triggered.connect(lambda: self.Delete_tableWidget(self.Ui.tableWidget_domain))
        self.clear_textEdit.triggered.connect(lambda: self.Clear_tableWidget(self.Ui.tableWidget_domain))
    def Copy_portscan_url_tableWidget(self):
        try:
            data = self.Ui.portscan_result.selectedItems()[0].text()+":"+self.Ui.portscan_result.selectedItems()[1].text()
            pyperclip.copy(data)
            self.Ui.statusBar.showMessage("复制成功!", 5000)
        except:
            pass
    def Copy_tableWidget(self, copy_obj,weizhi):
        try:
            data = ''
            if weizhi == 'all':
                # data = self.Ui.tableWidget_vuln.selectedItems()
                for i in copy_obj.selectedItems():
                    data += str(i.text()) + '  '
            else:
                data = copy_obj.selectedItems()[weizhi].text()
            # print(data)
            # 访问剪切板，存入值
            pyperclip.copy(data)
            self.Ui.statusBar.showMessage("复制成功!", 5000)
            # wincld.OpenClipboard()
            # wincld.EmptyClipboard()
            # wincld.SetClipboardData(win32con.CF_UNICODETEXT, data)
            # wincld.CloseClipboard()
        except:
            self.Ui.textEdit_log.append(
                "<a  style=\"color:red\">[%s]Error:请选择一个结果！</a>" % (
                    time.strftime('%H:%M:%S', time.localtime(time.time()))))


    def open_url(self):
        try:
            url = self.Ui.tableWidget_vuln.selectedItems()[0].text()
            webbrowser.open(url)
        except:
            self.Ui.textEdit_log.append(
                "<a  style=\"color:red\">[%s]Error:请选择一个结果！</a>" % (
                    time.strftime('%H:%M:%S', time.localtime(time.time()))))
    def open_domain_url(self, type):
        try:
            if type == "subdomain":
                url = self.Ui.tableWidget_domain.selectedItems()[1].text()
                webbrowser.open(url)
            elif type == "domain":
                url = self.Ui.tableWidget_domain.selectedItems()[0].text()
                webbrowser.open(url)
            elif type=="port_url":
                    if self.Ui.portscan_result.selectedItems()[2].text() in ["HTTP","HTTPS",'http','https']:
                        url = self.Ui.portscan_result.selectedItems()[2].text().lower()+"://"+self.Ui.portscan_result.selectedItems()[0].text()+":"+self.Ui.portscan_result.selectedItems()[1].text()
                    else:
                        url = "http://"+self.Ui.portscan_result.selectedItems()[0].text()+":"+self.Ui.portscan_result.selectedItems()[1].text()
                    # print(url)
                    webbrowser.open(url)
        except:
            box = QtWidgets.QMessageBox()
            box.warning(self, "错误", "请选择一个结果")


    def Clear_tableWidget(self, table_obj):
        for i in range(0, table_obj.rowCount()):  # 循环行
            table_obj.removeRow(0)

    def Delete_tableWidget(self, table_obj):
        table_obj.removeRow(table_obj.currentRow())  # 删除选中的行

    # 得到选中的方法
    def get_methods(self):
        all_data = []
        item = QtWidgets.QTreeWidgetItemIterator(self.Ui.treeWidget_Plugins)
        # 该类的value()即为QTreeWidgetItem
        while item.value():
            if not item.value().parent():  # 判断有没有父节点
                pass
            else:  # 输出所有子节点
                if item.value().checkState(0) == QtCore.Qt.Checked:
                    # print(item.value().text(0))
                    for cms in self.poc_cms_name_dict:
                        for poc in self.poc_cms_name_dict[cms]:
                            if poc['vuln_name'] == item.value().text(0):
                                poc['vuln_file'] = poc['vuln_file']
                                poc['FofaQuery_link'] = poc['FofaQuery_link']
                                poc['FofaQuery'] = poc['FofaQuery']
                                all_data.append(poc)
            item = item.__iadd__(1)
        # print(all_data)
        # 返回所有选中的数据
        return all_data

    # 得到选中的方法
    def get_domain_methods(self):
        all_data = []
        item = QtWidgets.QTreeWidgetItemIterator(self.Ui.treeWidget_domain_Plugins)
        # 该类的value()即为QTreeWidgetItem
        while item.value():
            if not item.value().parent():  # 判断有没有父节点
                if item.value().checkState(0) == QtCore.Qt.Checked:
                    # print(item.value().text(0))
                    for poc in self.domain_dict:
                        if poc['plugins_name'] == item.value().text(0):
                            all_data.append(poc)
            item = item.__iadd__(1)
        # print(all_data)
        # 返回所有选中的数据
        return all_data

    # 开始扫描
    def vuln_Start(self):
        try:
            timeout = int(self.Ui.comboBox_timeout.currentText())
        except:
            box = QtWidgets.QMessageBox()
            box.warning(self, "提示", "超时获取失败！")
            return
        jump_url = self.Ui.jump_url.isChecked()
        jump_fofa = self.Ui.jump_fofa.isChecked()
        threadnum = int(self.Ui.threadsnum.currentText())
        heads = self.Ui.vuln_scanner_textEdit_heads.toPlainText()
        target=[]
        if self.vuln_url_list:
            target = self.vuln_url_list
        else:
            url = self.Ui.lineEdit_vuln_url.text()
            if 'http://' in url or 'https://' in url:
                target.append(url.strip())
        poc_data = self.get_methods()  # 得到选中的数据
        self.vuln_scan_obj =  Vuln_Scanner(vuln_plugins_dir,self.__Logger,timeout,jump_url,jump_fofa,threadnum,heads,target,poc_data)
        self.vuln_scan_obj._data.connect(self.update_vulnscanner_data)  # 线程发过来的信号挂接到槽函数update_sum
        self.vuln_scan_obj._log.connect(self.update_vulnscanner_log)  # 线程发过来的信号挂接到槽函数update_sum
        self.Ui.pushButton_vuln_file.setEnabled(False)
        self.Ui.pushButton_vuln_start.setEnabled(False)
        self.Ui.pushButton_vuln_stop.setEnabled(True)
        self.Ui.textEdit_log.clear()
        self.vuln_scan_obj.start()  # 线程启动
    def update_vulnscanner_log(self,log):
        self.Ui.textEdit_log.append('[%s] %s'%(time.strftime('%H:%M:%S', time.localtime(time.time())),log))
        if "停止扫描" in log or "扫描结束" in log:
            self.Ui.pushButton_vuln_file.setEnabled(True)
            self.Ui.pushButton_vuln_start.setEnabled(True)
            self.Ui.pushButton_vuln_stop.setEnabled(False)


    def update_vulnscanner_data(self,data):

        # print(type,text)
        if data.get('Error_Info') :
            self.Ui.textEdit_log.append(
                "<p style=\"color:red\">[%s]Error:<br>Filename:%s<br>Error-Info:%s。</a>" % (
                time.strftime('%H:%M:%S'), data.get('poc_file'), data.get('Error_Info')))
        if data.get('Debug_Info')  and self.Ui.vuln_scanner_debug.isChecked():
            self.Ui.textEdit_log.append(
                "<p style=\"color:blue\">[%s]Debug:<br>Filename:%s<br>Debug-Info:%s。</a>" % (
                time.strftime('%H:%M:%S'), data.get('poc_file'), data.get('Debug_Info')))
        if data.get('Result'):
            url = data.get('url')
            filename = data.get('poc_file')
            poc_name = data.get('poc_name')
            self.Ui.textEdit_log.append(
                "<p style=\"color:green\">[%s]Result:%s----%s----%s。</a>" % (
                    (time.strftime('%H:%M:%S', time.localtime(time.time()))), url, poc_name, "存在"))
            self.Ui.tableWidget_vuln.setSortingEnabled(False)

            row = self.Ui.tableWidget_vuln.rowCount()  # 获取行数
            self.Ui.tableWidget_vuln.setRowCount(row + 1)
            urlItem = QTableWidgetItem(url)
            nameItem = QTableWidgetItem(poc_name)
            payloadItem = QTableWidgetItem(data.get('Result_Info'))
            resultItem = QTableWidgetItem("存在")
            filenameItem = QTableWidgetItem(filename)
            self.Ui.tableWidget_vuln.setItem(row, 0, urlItem)
            self.Ui.tableWidget_vuln.setItem(row, 1, nameItem)
            self.Ui.tableWidget_vuln.setItem(row, 3, resultItem)
            self.Ui.tableWidget_vuln.setItem(row, 2, filenameItem)
            self.Ui.tableWidget_vuln.setItem(row, 4, payloadItem)
            self.Ui.tableWidget_vuln.setSortingEnabled(True)

        elif not data.get('Result'):
            self.Ui.textEdit_log.append(
                "<p style=\"color:black\">[%s]Result:%s----%s----%s。</a>" % (
                time.strftime('%H:%M:%S'), data.get('url'), data.get('poc_name'), "不存在"))


    def vuln_Stop(self):
        self.Ui.textEdit_log.append(
            "<p style=\"color:black\">[%s]Info:发出停止信号，请等待...</a>" % (
                (time.strftime('%H:%M:%S', time.localtime(time.time())))))
        self.vuln_scan_obj.vuln_portQueue.queue.clear()
    def portscan_Start(self):

        ip = self.Ui.portscan_ip.toPlainText()
        port = self.Ui.portscan_port_list.toPlainText()
        if self.Ui.portscan_ping.isChecked():
            jp_flag = 1
        else:
            jp_flag = 0
        try:
            timeout = int(self.Ui.portscan_timeout.currentText())  # 获取文本
        except Exception as e:
            box = QtWidgets.QMessageBox()
            box.warning(self, "提示", "请输入正确的超时时间")
            return
        try:
            threads = int(self.Ui.portscan_threads.currentText())  # 获取文本
        except Exception as e:
            box = QtWidgets.QMessageBox()
            box.warning(self, "提示", "请设置正确的线程数量")
            return
        remove_port = self.Ui.portscan_paichuport_list.toPlainText()
        chrome_driver=''
        if self.Ui.portscan_screen.isChecked():
            for key, value in config_setup.items('Chrome'):
                if value == config_setup.get('Chrome', 'Chrome_path'):
                    chrome_driver = value
                    break

        self.portscan_log_file = (log_file_dir+"端口扫描-"+time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()) + '.log').replace(' ', '-').replace('-','').replace(':', '')
        self.portscan_obj = Port_Scan(remove_port,self.__Logger,ip, port, jp_flag, timeout, threads,chrome_driver)
        self.portscan_obj._data.connect(self.update_portscan)  # 线程发过来的信号挂接到槽函数update_sum
        self.portscan_obj._num.connect(self.update_portscan_num)  # 线程发过来的信号挂接到槽函数update_sum
        self.portscan_obj._count.connect(self.update_portscan_num_count)  # 线程发过来的信号挂接到槽函数update_sum
        self.portscan_obj._log.connect(self.update_portscan_log)  # 线程发过来的信号挂接到槽函数update_sum
        self.Ui.portscan_start.setEnabled(False)
        self.Ui.portscan_stop.setEnabled(True)
        self.Ui.portscan_add.setEnabled(True)
        self.Ui.portscan_logs.clear()
        self.Ui.progressBar_portscan.setValue(0)
        self.portscan_obj.start()  # 线程启动

    def update_portscan_num_count(self,count):
        self.Ui.progressBar_portscan.setMaximum(count)
    def update_portscan_num(self,num):
        step = self.Ui.progressBar_portscan.value()
        # num = int(self.Ui.portscan_num_go.text())
        # self.Ui.portscan_num_go.setText(str(num + 1))
        self.Ui.progressBar_portscan.setValue(step+num)

    def update_portscan_log(self,log):
        self.Ui.portscan_logs.append("[%s] %s"%(time.strftime('%H:%M:%S'),log))
        if log =="停止扫描" or log=="扫描结束":
                self.Ui.portscan_start.setEnabled(True)
                self.Ui.portscan_stop.setEnabled(False)
                self.Ui.portscan_add.setEnabled(False)

    def portscan_add(self):
        ip = self.Ui.portscan_ip.toPlainText()
        ip_all = ip.splitlines()
        i = threading.Thread(target=self.portscan_add_thread, args=(ip_all,))
        i.start()

    def portscan_add_thread(self,ip_all):
        ip_list = []
        for ip in ip_all:
            ip_list.extend(self.portscan_obj.get_ip_d_list(ip))
        for ip in ip_list:
            for j in self.portscan_obj.all_port_list:
                # print(port_list)
                self.portscan_obj.portscan_Queue.put(ip + ':' + str(j))
            self.Ui.portscan_logs.append("%s添加成功" % ip)
        step = self.portscan_obj.count
        add_count = len(self.portscan_obj.all_port_list) * len(ip_list) + step
        self.Ui.progressBar_portscan.setMaximum(add_count)

    def update_portscan(self,data):
        # print(data)
        self.portscan_R.acquire()
        row = self.Ui.portscan_result.rowCount()  # 获取行数
        self.Ui.portscan_result.setRowCount(row + 1)
        portscan_host = QTableWidgetItem(data.get('Host'))
        portscan_port = QTableWidgetItem(data.get('Port'))
        portscan_service = QTableWidgetItem(data.get('Service'))
        portscan_zhuangtai = QTableWidgetItem("Open")
        portscan_title = QTableWidgetItem(data.get('Title'))
        portscan_Banner = QTableWidgetItem(data.get('Banner'))
        portscan_screen_img = QTableWidgetItem(data.get('screen_img'))

        self.Ui.portscan_result.setSortingEnabled(False)

        self.Ui.portscan_result.setItem(row, 0, portscan_host)
        self.Ui.portscan_result.setItem(row, 1, portscan_port)
        self.Ui.portscan_result.setItem(row, 2, portscan_service)
        self.Ui.portscan_result.setItem(row, 3, portscan_zhuangtai)
        self.Ui.portscan_result.setItem(row, 4, portscan_title)
        self.Ui.portscan_result.setItem(row, 5, portscan_Banner)
        self.Ui.portscan_result.setItem(row, 6, portscan_screen_img)
        #自动调节列宽度
        self.Ui.portscan_result.setVisible(False)
        self.Ui.portscan_result.resizeColumnToContents(0)
        self.Ui.portscan_result.resizeColumnToContents(1)
        self.Ui.portscan_result.resizeColumnToContents(2)
        self.Ui.portscan_result.resizeColumnToContents(3)
        # self.Ui.portscan_result.resizeColumnToContents(4)
        # self.Ui.portscan_result.setColumnWidth(-1, 30)
        # self.Ui.portscan_result.setColumnWidth(-2, 30)
        self.Ui.portscan_result.setVisible(True)
        self.Ui.portscan_result.setSortingEnabled(True)
        self.portscan_R.release()
        save_portscan=open(self.portscan_log_file,'a')
        save_portscan.write(data.get('Host')+'--'+str(data.get('Port'))+'--'+data.get('Service')+'--Open--'+data.get('Title')+"\n")
        save_portscan.close()

    def domain_Start(self):
        timeout = int(self.Ui.comboBox_doamin_timeout.currentText())
        threadnum = int(self.Ui.doamin_threadsnum.currentText())
        heads = self.Ui.doamin_textEdit_heads.toPlainText()
        heads_dict = {}
        heads = heads.splitlines()
        for head in heads:
            head = head.split(':')
            heads_dict[head[0].strip()] = head[1].strip()
        self.Ui.textEdit_doamin_log.clear()
        target = []  # 存放扫描的URL
        if self.domain_url_list:
            target = self.domain_url_list
        else:
            url = self.Ui.lineEdit_doamin_url.text()
            if url != "":
                target.append(url.strip())
        if not target:
            self.Ui.textEdit_doamin_log.append(
                "<p style=\"color:black\">[%s]Info:未获取到域名地址。</a>" % (
                    time.strftime('%H:%M:%S', time.localtime(time.time()))))
            return 0
        if self.Ui.doamin_ip.isChecked():
            get_ip = 1
        else:
            get_ip = 0
        if self.Ui.doamin_title.isChecked():
            get_title = 1
        else:
            get_title = 0
        poc_data = self.get_domain_methods()  # 得到选中的数据
        # print(poc_data)
        chrome_driver=''
        if self.Ui.doamin_screen.isChecked():
            for key, value in config_setup.items('Chrome'):
                if value == config_setup.get('Chrome', 'Chrome_path'):
                    chrome_driver = value
                    break
        if not poc_data:
            self.Ui.textEdit_doamin_log.append(
                "<p style=\"color:black\">[%s]Info:未选择插件。</a>" % (
                    time.strftime('%H:%M:%S', time.localtime(time.time()))))
            return 0
        else:
            self.domain_obj = Domain_Start(self, domain_plugins_dir, target, poc_data, heads_dict,
                                    threadnum, timeout, get_ip, get_title,self.__Logger,chrome_driver)  # 创建一个线程
            self.domain_obj._sum.connect(self.update_domain)  # 线程发过来的信号挂接到槽函数update_sum
            self.Ui.pushButton_doamin_start.setEnabled(False)
            self.Ui.pushButton_doamin_file.setEnabled(False)
            self.Ui.pushButton_doamin_stop.setEnabled(True)

            self.domain_obj.start()  # 线程启动

    def domain_Stop(self):
        self.Ui.textEdit_doamin_log.append(
            "<p style=\"color:black\">[%s]Info:发出停止信号，请等待...</a>" % (
                (time.strftime('%H:%M:%S', time.localtime(time.time())))))
        self.domain_obj.domain_Queue.queue.clear()
        self.domain_obj.stop_flag=1

    def portscan_Stop(self):
        self.Ui.portscan_logs.append("发出停止信号，请等待...")
        self.portscan_obj.portscan_Queue.queue.clear()
        self.portscan_obj.stop_flag = 1

    def update_domain(self, result):
        if result.get('Result'):
            domain = result.get('domain')
            subdomain = result.get('subdomain')
            subdomain_ip = result.get('subdomain_ip')
            subdomain_title = result.get('subdomain_title')
            subdomain_screen_img = result.get('screen_img')
            # print(subdomain_screen_img)

            self.Ui.tableWidget_domain.setSortingEnabled(False)
            row = self.Ui.tableWidget_domain.rowCount()  # 获取行数
            self.Ui.tableWidget_domain.setRowCount(row + 1)
            domain = QTableWidgetItem(domain)
            subdomain = QTableWidgetItem(subdomain)
            subdomain_ip = QTableWidgetItem(subdomain_ip)
            subdomain_title = QTableWidgetItem(subdomain_title)
            subdomain_screen_img = QTableWidgetItem(subdomain_screen_img)


            self.Ui.tableWidget_domain.setItem(row, 0, domain)
            self.Ui.tableWidget_domain.setItem(row, 1, subdomain)
            self.Ui.tableWidget_domain.setItem(row, 2, subdomain_ip)
            self.Ui.tableWidget_domain.setItem(row, 3, subdomain_title)
            self.Ui.tableWidget_domain.setItem(row, 4, subdomain_screen_img)

            self.Ui.tableWidget_domain.setSortingEnabled(True)

        if result.get('Error_Info'):
            self.Ui.textEdit_doamin_log.append(
                "<p style=\"color:red\">[%s]Error:<br>Error-Info:%s。</a>" % (
                    time.strftime('%H:%M:%S'), result.get('Error_Info')))
        if result.get('Debug_Info') and self.Ui.doamin_debug.isChecked():
                self.Ui.textEdit_doamin_log.append(
                    "<p style=\"color:blue\">[%s]Debug:<br>Debug-Info:%s。</a>" % (
                        time.strftime('%H:%M:%S'), result.get('Debug_Info')))
    # 初始化加载vuln插件
    def load_vuln_plugins(self):
        if not os.path.isfile(DB_NAME):
            box = QtWidgets.QMessageBox()
            box.warning(self, "提示", "数据文件不存在，正在重新加载数据库！")
            self.vuln_reload_Plugins()
            return 0
        # 加载漏洞扫描模块
        try:
            # 列出所有数据
            sql_poc = "SELECT cms_name,vuln_name,vuln_file,FofaQuery_link,FofaQuery from vuln_poc where ispoc !=''"
            poc_dict = self.sql_search(sql_poc, 'dict')
            # print(values)
        except Exception as e:
            box = QtWidgets.QMessageBox()
            box.warning(self, "提示", "数据文件错误：\n%s" % e)
            return 0
        # 将查询的值组合为字典包含列表的形式
        self.poc_cms_name_dict = {}
        for cms in poc_dict:
            self.poc_cms_name_dict[cms['cms_name']] = []
        # print(cms_name)
        for cms in poc_dict:
            poc_cms_sing = {}
            poc_cms_sing['cms_name'] = cms['cms_name']
            poc_cms_sing['vuln_name'] = cms['vuln_name']
            poc_cms_sing['vuln_file'] = cms['vuln_file']
            poc_cms_sing['FofaQuery_link'] = cms['FofaQuery_link']
            poc_cms_sing['FofaQuery'] = cms['FofaQuery']
            self.poc_cms_name_dict[cms['cms_name']].append(poc_cms_sing)
        for cms in self.poc_cms_name_dict:
            # 设置root为self.treeWidget_Plugins的子树，故root是根节点
            root = QTreeWidgetItem(self.Ui.treeWidget_Plugins)
            root.setText(0, cms)  # 设置根节点的名称
            # root.setCheckState(0, QtCore.Qt.Unchecked)  # 开启复选框
            root.setFlags(QtCore.Qt.ItemIsSelectable|QtCore.Qt.ItemIsDragEnabled|QtCore.Qt.ItemIsDropEnabled|QtCore.Qt.ItemIsUserCheckable|QtCore.Qt.ItemIsEnabled|QtCore.Qt.ItemIsTristate)

            # print(cms_name[cms])
            for cms_single in self.poc_cms_name_dict[cms]:
                # 为root节点设置子结点
                child1 = QTreeWidgetItem(root)
                child1.setText(0, cms_single['vuln_name'])
                child1.setCheckState(0, QtCore.Qt.Unchecked)
        # self.Ui.treeWidget_Plugins.itemChanged.connect(self.handleChanged)
        self.Ui.treeWidget_Plugins.doubleClicked.connect(self.Show_Plugins_info)
        self.Ui.textEdit_log.append(
            "<p style=\"color:green\">[%s]Success:插件加载完成，共%s个。</a>" % (
            time.strftime('%H:%M:%S', time.localtime(time.time())), len(poc_dict)))

    # 初始化加载exp插件
    def load_exp_plugins(self):
        # print(self.poc_dict)
        sql_exp = "SELECT cms_name,vuln_name,vuln_file,vuln_description,FofaQuery_link,FofaQuery from vuln_poc where isexp !=''"
        exp_dict = self.sql_search(sql_exp, 'dict')

        # 将查询的值组合为字典包含列表的形式
        self.exp_cms_name_dict = {}
        for cms in exp_dict:
            self.exp_cms_name_dict[cms['cms_name']] = []
        # print(exp_cms_name_dict)
        for exp_cms in exp_dict:
            # print(cms['cmsname'] )
            # if cms['cmsname'] in cms_name.keys():
            exp_cms_sing = {}
            exp_cms_sing['cms_name'] = exp_cms['cms_name']
            exp_cms_sing['vuln_name'] = exp_cms['vuln_name']
            exp_cms_sing['vuln_file'] = exp_cms['vuln_file']
            exp_cms_sing['vuln_description'] = exp_cms['vuln_description']
            self.exp_cms_name_dict[exp_cms['cms_name']].append(exp_cms_sing)
        # print(exp_cms_name_dict)
        self.Ui.vuln_name.clear()
        self.Ui.vuln_type.clear()
        for cms in self.exp_cms_name_dict:
            self.Ui.vuln_type.addItem(cms)
        for exp_methods in list(self.exp_cms_name_dict.values())[0]:
            # print(exp_methods)
            self.Ui.vuln_name.addItem(exp_methods['vuln_name'])
            self.Ui.vuln_exp_textEdit_info.setText("漏洞信息会显示在这里！")
        #加载本地shell文件
        for root, dirs, files in os.walk(exp_plugins_dir):
            for file in files:
                if file[0] != ".":
                    self.Ui.vuln_exp_comboBox_shell.addItem(file)
        self.change_exp_combox()

    #初始化加载note插件

    def load_note_plugins(self):
        self.Ui.treeWidget_note.clear()
        # 加载漏洞扫描模块
        try:
            # 列出所有数据
            sql_note = "SELECT note_category,note_name from note where note_category !='' and note_name !=''"
            note_dict = self.sql_search(sql_note, 'dict')
            # print(values)
        except Exception as e:
            box = QtWidgets.QMessageBox()
            box.warning(self, "提示", "数据文件错误：\n%s" % e)
            return 0
        # 将查询的值组合为字典包含列表的形式
        main_dict={}
        for single_data in note_dict:
            main_dict[single_data['note_category']] = []
        # print(cms_name)
        for single_data in note_dict:
            main_dict[single_data['note_category']].append(single_data['note_name'])
        for single_data in main_dict:
            # 设置root为self.treeWidget_note，故root是根节点
            root = QTreeWidgetItem(self.Ui.treeWidget_note)
            root.setText(0, single_data)  # 设置根节点的名称
            # root.setCheckState(0, QtCore.Qt.Unchecked)  # 开启复选框
            # root.setFlags(
            #     QtCore.Qt.ItemIsSelectable | QtCore.Qt.ItemIsDragEnabled | QtCore.Qt.ItemIsDropEnabled | QtCore.Qt.ItemIsUserCheckable | QtCore.Qt.ItemIsEnabled | QtCore.Qt.ItemIsTristate)

            # print(cms_name[cms])
            for cms_single in main_dict[single_data]:
                # 为root节点设置子结点
                child1 = QTreeWidgetItem(root)
                child1.setText(0, cms_single)
                # child1.setCheckState(0, QtCore.Qt.Unchecked)
        # self.Ui.treeWidget_note.itemChanged.connect(self.handleChanged)
        self.Ui.treeWidget_note.doubleClicked.connect(self.Show_note_info)


    # 初始化加载子域名插件
    def load_domain_plugins(self):
        # 设置漏洞扫描表格属性  列宽度
        # self.Ui.tableWidget_domain.resizeColumnsToContents()  # 自动列宽
        # self.Ui.tableWidget_domain.setColumnWidth(0, 250)
        # self.Ui.tableWidget_domain.setColumnWidth(1, 300)
        # self.Ui.tableWidget_domain.setColumnWidth(2, 200)
        if not os.path.isfile(DB_NAME):
            box = QtWidgets.QMessageBox()
            box.warning(self, "提示", "数据文件不存在，正在重新加载数据库！")
            self.vuln_reload_Plugins()
            return 0
        # 加载漏洞扫描模块
        try:
            # 列出所有数据
            domain_poc = "SELECT * from domain"
            poc_dict = self.sql_search(domain_poc, 'dict')
            # print(values)
        except Exception as e:
            box = QtWidgets.QMessageBox()
            box.warning(self, "提示", "数据文件错误：\n%s" % e)
            return 0
        # 将查询的值组合为字典包含列表的形式
        self.domain_dict = poc_dict
        # print(cms_name)

        for cms_single in self.domain_dict:
            # 设置root为self.treeWidget_Plugins的子树，故root是根节点
            root = QTreeWidgetItem(self.Ui.treeWidget_domain_Plugins)
            root.setText(0, cms_single['plugins_name'])  # 设置根节点的名称
            root.setCheckState(0, QtCore.Qt.Unchecked)  # 开启复选框
            # # 为root节点设置子结点
            # child1 = QTreeWidgetItem(root)
            # child1.setText(0, cms_single['plugins_name'])
            # child1.setCheckState(0, Qt.Unchecked)
        # self.Ui.treeWidget_domain_Plugins.itemChanged.connect(self.handleChanged)
        # self.Ui.treeWidget_Plugins.doubleClicked.connect(self.Show_Plugins_info)
        self.Ui.textEdit_doamin_log.append(
            "<p style=\"color:green\">[%s]Success:插件加载完成，共%s个。</a>" % (
            time.strftime('%H:%M:%S', time.localtime(time.time())), len(poc_dict)))

    def Show_Plugins_info(self):
        poc_name = self.Ui.treeWidget_Plugins.currentItem().text(0)
        # 列出所有数据
        sql = "SELECT *  from vuln_poc where vuln_name='%s'" % poc_name
        values = self.sql_search(sql, 'dict')
        # print(values)
        try:
            self.dialog.close()
        except Exception as e:
            pass
        if len(values) != 0:
            self.WChild_info = Ui_From_Vuln_Info()
            self.dialog = QtWidgets.QDialog(self)

            self.WChild_info.setupUi(self.dialog)
            self.dialog.setWindowIcon(QtGui.QIcon('Conf/main.png'))
            self.dialog.show()
            # print(values)
            self.WChild_info.vuln_name.setText(values[0]['vuln_name'])
            self.WChild_info.cms_name.setText(values[0]['cms_name'])
            if values[0]['isexp']:
                self.WChild_info.vuln_exp.setText("True")
            else:
                self.WChild_info.vuln_exp.setText("暂无")
            if values[0]['ispoc']:
                self.WChild_info.vuln_poc.setText("True")
            else:
                self.WChild_info.vuln_poc.setText("暂无")

            self.WChild_info.vuln_file.setText(vuln_plugins_dir + values[0]['cms_name'] + '/' + values[0]['vuln_file'])
            self.WChild_info.vuln_url.setText(
                '<a href="' + values[0]['vuln_referer'] + '">' + values[0]['vuln_referer'] + '</a>')
            self.WChild_info.vuln_miaoshu.setText(values[0]['vuln_description'])
            self.WChild_info.vuln_solution.setText(values[0]['vuln_solution'])
            self.WChild_info.vuln_identifier.setText(values[0]['vuln_identifier'])
            return 0
        else:
            return

    # # 父节点关联子节点
    # def handleChanged(self, item, column):
    #     count = item.childCount()
    #     # print dir(item)
    #     if item.checkState(column) == QtCore.Qt.Checked:
    #         # print "checked", item, item.text(column)
    #         for f in range(count):
    #             item.child(f).setCheckState(0, QtCore.Qt.Checked)
    #     if item.checkState(column) == QtCore.Qt.Unchecked:
    #         # print "unchecked", item, item.text(column)
    #         for f in range(count):
    #             item.child(f).setCheckState(0, QtCore.Qt.Unchecked)


        #  self.Ui.treeWidget_Plugins.setSelectionMode(QAbstractItemView.ExtendedSelection)  # 设置item可以多选
        # self.tree.itemChanged.connect(self.handleChanged)
        # self.Ui.treeWidget_Plugins.addTopLevelItem(root)
    def Show_note_info(self):
        box = QtWidgets.QMessageBox()
        noteitem = self.Ui.treeWidget_note.currentItem()
        if noteitem:
            note_name = noteitem.text(0)
        else:
            box.information(self, "Faile", "请选择一条数据！")
            return
        categoryitem  = self.Ui.treeWidget_note.currentItem().parent()
        if not categoryitem:
            return
        note_category  = categoryitem.text(0)
        # print(categoryitem)

        # 列出所有数据
        sql = "SELECT note_contents  from note where note_category='%s' and note_name='%s'" % (note_category,note_name)
        values = self.sql_search(sql)
        if values:
            self.Ui.textEdit_note.setHtml(values[0][0])
            self.Ui.lineEdit_note_name.setText(note_name)
            self.Ui.lineEdit_note_fenlei.setText(note_category)
    def save_note_info(self):
        note_category=self.Ui.lineEdit_note_fenlei.text()
        note_name=self.Ui.lineEdit_note_name.text()
        box = QtWidgets.QMessageBox()
        if note_category and note_name:
            # 连接数据库。如果数据库不存在的话，将会自动创建一个 数据库
            conn = sqlite3.connect(DB_NAME)
            # 创建一个游标 curson
            cursor = conn.cursor()
            note_contents = self.Ui.textEdit_note.toHtml()
            select_sql = "select * from note where note_category='%s' and note_name='%s';"%(note_category,note_name)
            select_result = self.sql_search(select_sql)
            if select_result:
                sql = "UPDATE note SET note_contents=? WHERE note_name=? and note_category=?;"
            else:
                sql = "INSERT INTO note( note_contents,note_name,note_category)VALUES ( ?,?,?);"
            cursor.execute(sql, (note_contents,note_name,note_category))
            conn.commit()  # 提交
            cursor.close()
            conn.close()
            box.information(self, "Success", "保存成功！")
            self.load_note_plugins()
        else:
            box.information(self, "Faile", "保存失败,文章名称或分类为空！")
    def delete_note_info(self):
        box = QtWidgets.QMessageBox()
        noteitem = self.Ui.treeWidget_note.currentItem()
        if noteitem:
            note_name = noteitem.text(0)
        else:
            box.information(self, "Faile", "请选择一条数据！")
            return
        categoryitem  = self.Ui.treeWidget_note.currentItem().parent()
        if not categoryitem:
            return
        note_category  = categoryitem.text(0)
        # print(categoryitem)

        # 列出所有数据
        sql = "DELETE from note where note_category='%s' and note_name='%s'" % (note_category,note_name)
        result_flag = self.sql_search(sql,'delete')
        if result_flag:
            box.information(self, "Success", "删除成功！")
            self.load_note_plugins()
            self.Ui.textEdit_note.clear()
            self.Ui.lineEdit_note_fenlei.clear()
            self.Ui.lineEdit_note_name.clear()
        else:
            box.information(self, "Faile", "删除失败！")






    # 导入文件列表
    def vuln_import_file(self,lineEdit_vuln_obj,textEdit_log_obj,type):
        url_list = []
        filename = self.file_open(r"Text Files (*.txt);;All files(*.*)")
        try:
            if os.path.isfile(filename):
                textEdit_log_obj.append(
                    "<a  style=\"color:black\">[%s]Info:正在从文件中读取URL...</a>" % (
                        time.strftime('%H:%M:%S', time.localtime(time.time()))))
                f = open(filename, 'r', encoding='utf-8')
                for line in f.readlines():
                    if 'http' in line:
                        line = line.replace('\n', '').strip()
                        url_list.append(line)
                textEdit_log_obj.append(
                    "<a  style=\"color:black\">[%s]Info:读取完成，共加载%s条。</a>" % (
                        (time.strftime('%H:%M:%S', time.localtime(time.time()))), len(self.vuln_url_list)))
            lineEdit_vuln_obj.setText(filename)
            if type=='vuln_scanner':
                self.vuln_url_list = url_list
            if type=='domain_scanner':
                self.domain_url_list = url_list

        except Exception as e:
            textEdit_log_obj.append(
                "<a  style=\"color:red\">[%s]Error:文件打开失败！</a>" % (
                    time.strftime('%H:%M:%S', time.localtime(time.time()))))
            pass
    #
    # # 导入文件列表
    def import_file(self,path_obj,type='',filename_obj=''):
        filename = self.file_open(r"All files(*.*)")
        try:
            data=''
            if os.path.isfile(filename):
                f = open(filename, 'r', encoding='utf-8')
                data= f.read()
                f.close()
                if data:
                    if type=="PlainText":
                        path_obj.setPlainText(data)
                    else:
                        path_obj.setText(data)
                    if filename_obj:
                        filename = os.path.basename(filename)
                        filename_obj.setText(filename)
        except Exception as e:
            # print(str(e))
            box = QtWidgets.QMessageBox()
            box.warning(self, "错误", "文件打开失败，请确实编码是否是utf-8")


    # 导出扫描结果
    def export_file(self, table_obj, log_obj):
        data = []
        comdata = []
        if table_obj.rowCount()>0:
            for lll in range(0, table_obj.columnCount()):  # 循环列
                data.append(table_obj.horizontalHeaderItem(lll).text())  # 空格分隔
            comdata.append(list(data))
            data = []
            for i in range(0, table_obj.rowCount()):  # 循环行
                for j in range(0, table_obj.columnCount()):  # 循环列
                    if table_obj.item(i, j) != None:  # 有数据
                        data.append(table_obj.item(i, j).text())  # 空格分隔
                comdata.append(list(data))
                data = []
            if len(comdata) > 0:
                path = (time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()) + '.csv').replace(' ', '-').replace('-',
                                                                                                                 '').replace(
                    ':', '')
                # print(path)
                file_name = self.file_save(path)
                if file_name != "":
                    with open(file_name, 'w',encoding='utf-8',newline="") as f:
                        writer = csv.writer(f)
                        for row in comdata:
                            writer.writerow(row)
                    f.close()
                    box = QtWidgets.QMessageBox()
                    box.information(self, "Success", "导出成功！\n文件位置：" + file_name)
                    # self.Ui.statusBar.showMessage("Success", "导出成功！\n文件位置：" + file_name, 5000)
                else:
                    # box2= QtWidgets.QMessageBox()
                    # box2.warning(self, "Error", "保存失败！文件名错误！" )
                    pass
            else:
                try:
                    box = QtWidgets.QMessageBox()
                    box.warning(self, "提示", "表格无结果！")
                    if log_obj !='':
                        log_obj.append(
                        "[%s]Faile:没有结果！" % (time.strftime('%H:%M:%S', time.localtime(time.time()))))
                except:
                    pass

    # 显示插件
    def vuln_ShowPlugins(self):
        self.form2 = QtWidgets.QWidget()
        self.vuln_widget = Ui_Form_Vuln()
        self.vuln_widget.setupUi(self.form2)
        self.form2.setStyleSheet(qss_style)
        self.form2.setWindowIcon(QtGui.QIcon('Conf/main.png'))
        self.form2.show()
        self.vuln_update_table_data()
        self.vuln_widget.pushButton_show_Plugins_add.clicked.connect(self.vuln_plugins_add)
        self.vuln_widget.pushButton_show_Plugins_delete.clicked.connect(self.vuln_plugins_delete)
        self.vuln_widget.pushButton_show_Plugins_edit.clicked.connect(self.vuln_plugins_edit)
        self.vuln_widget.pushButton_show_Plugins_reload.clicked.connect(self.vuln_update_table_data)

        self.vuln_widget.show_Plugins_comboBox_cms_name.currentIndexChanged.connect(self.show_plugins_go)  # comboBox事件选中触发刷新
        self.vuln_widget.show_Plugins_comboBox_vuln_class.currentIndexChanged.connect(self.show_plugins_go)  # comboBox事件选中触发刷新
    def vuln_plugins_add(self):
        sql = 'SELECT distinct cms_name from vuln_poc'
        cms_name_data = self.sql_search(sql)
        self.form3_vuln_edit = QtWidgets.QWidget()
        self.widget_vuln_edit = Ui_Form_Vuln_Edit()
        self.widget_vuln_edit.setupUi(self.form3_vuln_edit)
        self.form3_vuln_edit.setStyleSheet(qss_style)
        self.form3_vuln_edit.setWindowIcon(QtGui.QIcon('Conf/main.png'))
        self.form3_vuln_edit.show()
        for cms_name in cms_name_data:
            self.widget_vuln_edit.comboBox_vuln_cms.addItem(cms_name[0])
        self.highlighter = PythonHighlighter(self.widget_vuln_edit.vuln_exp_textEdit_shell.document())
        f=open(vuln_plugins_template,'r',encoding='utf-8')
        data = f.read()
        f.close()
        self.widget_vuln_edit.vuln_exp_textEdit_shell.setText(data)
        #插件保存
        self.widget_vuln_edit.pushButton_vuln_save.clicked.connect(self.vuln_plugins_save)
    def vuln_plugins_delete(self):
        obj = self.vuln_widget.show_Plugins.selectedItems()
        id = obj[0].text()

        filename =vuln_plugins_dir+ obj[1].text()+'/'+obj[7].text()
        sql = "DELETE FROM vuln_poc WHERE id="+id
        result_flag = self.sql_search(sql,'delete')
        if result_flag:
            box = QtWidgets.QMessageBox()
            self.vuln_update_table_data()
            reply = QMessageBox.question(window, '插件删除',"数据库已删除，是否删除本地文件",QMessageBox.Yes | QMessageBox.No,QMessageBox.Yes)
            if reply == QMessageBox.Yes:
                os.remove(filename)
                if not os.path.exists(filename):
                    box.information(self, "Success", "文件删除成功！")
                else:
                    box.information(self, "Success", "文件删除失败，请手动删除！")
            else:
                pass
    #刷新显示的数据
    def vuln_update_table_data(self):
        self.vuln_widget.show_Plugins_comboBox_cms_name.clear()
        self.vuln_widget.show_Plugins_comboBox_vuln_class.clear()
        sql = "SELECT * from vuln_poc"
        values = self.sql_search(sql, 'dict')
        i = 0
        self.vuln_widget.show_Plugins.setRowCount(len(values))
        sql2 = "SELECT distinct cms_name from vuln_poc"
        sql_vuln_class = "SELECT distinct vuln_class from vuln_poc where vuln_class!='' and vuln_class not null"
        cms_name_data = self.sql_search(sql2)
        vuln_class_data = self.sql_search(sql_vuln_class)
        # 添加查询列表
        self.vuln_widget.show_Plugins_comboBox_cms_name.addItem("ALL")
        self.vuln_widget.show_Plugins_comboBox_vuln_class.addItem("ALL")
        for cms_name in cms_name_data:
            self.vuln_widget.show_Plugins_comboBox_cms_name.addItem(cms_name[0])
        for vuln_class in vuln_class_data:
            self.vuln_widget.show_Plugins_comboBox_vuln_class.addItem(vuln_class[0])
        # print(cms_name[0])
        self.vuln_widget.show_Plugins.setSortingEnabled(False)

        for single in values:
            # print(single)
            id = QTableWidgetItem(str(single['id']))
            cms_name = QTableWidgetItem(str(single['cms_name']))
            vuln_name = QTableWidgetItem(str(single['vuln_name']))
            vuln_class = QTableWidgetItem(str(single['vuln_class']))
            vuln_identifier = QTableWidgetItem(str(single['vuln_identifier']))
            vuln_referer = QTableWidgetItem(str(single['vuln_referer']))
            vuln_description = QTableWidgetItem(str(single['vuln_description']))
            vuln_file = QTableWidgetItem(str(single['vuln_file']))
            vuln_author = QTableWidgetItem(str(single['vuln_author']))
            vuln_solution = QTableWidgetItem(str(single['vuln_solution']))
            self.vuln_widget.show_Plugins.setItem(i, 0, id)
            self.vuln_widget.show_Plugins.setItem(i, 1, cms_name)
            self.vuln_widget.show_Plugins.setItem(i, 2, vuln_name)
            self.vuln_widget.show_Plugins.setItem(i, 3, vuln_class)
            self.vuln_widget.show_Plugins.setItem(i, 4, vuln_identifier)
            self.vuln_widget.show_Plugins.setItem(i, 5, vuln_referer)
            self.vuln_widget.show_Plugins.setItem(i, 6, vuln_description)
            self.vuln_widget.show_Plugins.setItem(i, 7, vuln_file)
            self.vuln_widget.show_Plugins.setItem(i, 8, vuln_author)
            self.vuln_widget.show_Plugins.setItem(i, 9, vuln_solution)
            i = i + 1
        self.vuln_widget.show_Plugins.setVisible(False)
        self.vuln_widget.show_Plugins.resizeColumnToContents(0)
        self.vuln_widget.show_Plugins.resizeColumnToContents(1)
        self.vuln_widget.show_Plugins.resizeColumnToContents(2)
        self.vuln_widget.show_Plugins.resizeColumnToContents(3)
        self.vuln_widget.show_Plugins.resizeColumnToContents(4)
        self.vuln_widget.show_Plugins.resizeColumnToContents(8)

        # self.vuln_widget.show_Plugins.resizeColumnsToContents()
        self.vuln_widget.show_Plugins.setVisible(True)
        self.vuln_widget.show_Plugins.setSortingEnabled(True)
    def vuln_plugins_edit(self):
        try:
            id = self.vuln_widget.show_Plugins.selectedItems()[0].text()
        except:
            box = QtWidgets.QMessageBox()
            box.information(self, "Error", "请选择一个插件！")
            return
        if id :
            sql = 'SELECT distinct * from vuln_poc where id='+id
            cms_name_data = self.sql_search(sql,'dict')
            self.form3_vuln_edit = QtWidgets.QWidget()
            self.widget_vuln_edit = Ui_Form_Vuln_Edit()
            self.widget_vuln_edit.setupUi(self.form3_vuln_edit)
            self.form3_vuln_edit.setStyleSheet(qss_style)
            self.form3_vuln_edit.setWindowIcon(QtGui.QIcon('Conf/main.png'))
            self.form3_vuln_edit.show()
            self.widget_vuln_edit.comboBox_vuln_cms.addItem(cms_name_data[0]['cms_name'])
            self.highlighter = PythonHighlighter(self.widget_vuln_edit.vuln_exp_textEdit_shell.document())
            plugins = vuln_plugins_dir+cms_name_data[0]['cms_name']+'/'+cms_name_data[0]['vuln_file']
            f=open(plugins,'r',encoding='utf-8')
            data = f.read()
            f.close()
            self.widget_vuln_edit.vuln_exp_textEdit_shell.setText(data)
            self.widget_vuln_edit.label_vuln_id.setText(id)
            self.widget_vuln_edit.lineEdit_vuln_file.setText(cms_name_data[0]['vuln_file'])
            #插件保存
            self.widget_vuln_edit.pushButton_vuln_save.clicked.connect(self.vuln_plugins_save)
        else:
            box = QtWidgets.QMessageBox()
            box.information(self, "Error", "请选择一个插件！")

    def vuln_plugins_save(self): #需要插入数据库一条保存的数据
        try:
            cms_name = self.widget_vuln_edit.comboBox_vuln_cms.currentText()
            fine_name =  self.widget_vuln_edit.lineEdit_vuln_file.text()
            if fine_name:
                plugins_text = self.widget_vuln_edit.vuln_exp_textEdit_shell.toPlainText()
                if not os.path.exists(vuln_plugins_dir+'/'+cms_name):
                    os.makedirs(vuln_plugins_dir+'/'+cms_name)
                else:
                    if fine_name[:8] != "Plugins_":
                        fine_name ='Plugins_' + fine_name
                    if not fine_name.endswith('.py'):
                        fine_name=fine_name+'.py'
                    plugins_filename = vuln_plugins_dir + '/' + cms_name +'/' + fine_name
                    f=open(plugins_filename,'w',encoding='utf-8')
                    f.write(plugins_text)
                    f.close()
                    nnnnnnnnnnnn1 = importlib.machinery.SourceFileLoader(plugins_filename[:-3],plugins_filename).load_module()
                    vuln_info = nnnnnnnnnnnn1.vuln_info()
                    if vuln_info.get('vuln_class'):
                        vuln_class = vuln_info.get('vuln_class')
                    else:
                        vuln_class = '未分类'
                    if vuln_info.get('FofaQuery_link'):
                        FofaQuery_link = (vuln_info.get('FofaQuery_link'))
                    else:
                        FofaQuery_link = ''
                    if vuln_info.get('FofaQuery'):
                        FofaQuery = vuln_info.get('FofaQuery')
                    else:
                        FofaQuery = ''
                    insert_sql = 'insert into vuln_poc  (id,cms_name,vuln_file,vuln_name,vuln_author,vuln_referer,vuln_description,vuln_identifier,vuln_solution,ispoc,isexp,vuln_class,FofaQuery_link,FofaQuery,target) values (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)'
                    conn = sqlite3.connect(DB_NAME)
                    # 创建一个游标 curson
                    cursor = conn.cursor()
                    id_sql = "select id from vuln_poc  order by id desc limit 1"
                    cursor.execute(id_sql)
                    id_values = cursor.fetchall()
                    # print(id_values[0][0])
                    # 将数据插入到表中
                    cursor.execute(insert_sql, (str(int(id_values[0][0])+1), cms_name, fine_name, vuln_info['vuln_name'], vuln_info['vuln_author'],
                        vuln_info['vuln_referer'], vuln_info['vuln_description'],
                        vuln_info['vuln_identifier'], vuln_info['vuln_solution'], vuln_info['ispoc'],
                        vuln_info['isexp'], vuln_class, FofaQuery_link, FofaQuery, '[]'))
                    conn.commit()  # 提交
                    cursor.close()
                    conn.close()
                    self.vuln_update_table_data()
                    box = QtWidgets.QMessageBox()
                    box.information(self, "Error", "保存成功！")
                    self.form3_vuln_edit.close()
            else:
                box = QtWidgets.QMessageBox()
                box.information(self, "Error", "请输入插件名称！")
        except Exception as e:
            box = QtWidgets.QMessageBox()
            box.information(self, "Error", "保存失败\n！"+str(e))



    def domain_ShowPlugins(self):
        self.form3 = QtWidgets.QWidget()
        self.domain_widget = Ui_Form_Domain()
        self.domain_widget.setupUi(self.form3)

        self.form3.setStyleSheet(qss_style)
        self.form3.setWindowIcon(QtGui.QIcon('Conf/main.png'))
        self.form3.show()
        sql = "SELECT * from domain"
        values = self.sql_search(sql, 'dict')
        i = 0
        self.domain_widget.domainplugins.setRowCount(len(values))
        self.domain_widget.domainplugins.setSortingEnabled(False)

        for single in values:
            # print(single)
            id = QTableWidgetItem(str(single['id']))
            plugins_file = QTableWidgetItem(str(single['plugins_file']))
            plugins_name = QTableWidgetItem(str(single['plugins_name']))
            plugins_author = QTableWidgetItem(str(single['plugins_author']))
            plugins_description = QTableWidgetItem(str(single['plugins_description']))
            plugins_key1 = QTableWidgetItem(str(single['plugins_key1']))
            plugins_key2 = QTableWidgetItem(str(single['plugins_key2']))
            plugins_key3 = QTableWidgetItem(str(single['plugins_key3']))
            self.domain_widget.domainplugins.setItem(i, 0, id)
            self.domain_widget.domainplugins.setItem(i, 1, plugins_name)
            self.domain_widget.domainplugins.setItem(i, 2, plugins_file)
            self.domain_widget.domainplugins.setItem(i, 3, plugins_author)
            self.domain_widget.domainplugins.setItem(i, 4, plugins_key1)
            self.domain_widget.domainplugins.setItem(i, 5, plugins_key2)
            self.domain_widget.domainplugins.setItem(i, 6, plugins_key3)
            self.domain_widget.domainplugins.setItem(i, 7, plugins_description)
            i = i + 1
        self.domain_widget.domainplugins.setVisible(False)
        # self.domain_widget.domainplugins.resizeColumnsToContents()
        self.domain_widget.domainplugins.resizeColumnToContents(0)
        self.domain_widget.domainplugins.resizeColumnToContents(1)
        self.domain_widget.domainplugins.resizeColumnToContents(2)
        self.domain_widget.domainplugins.resizeColumnToContents(3)
        self.domain_widget.domainplugins.setVisible(True)
        self.domain_widget.domainplugins.setSortingEnabled(True)

    # 单击列表刷新显示控件
    def show_plugins_go(self):
        self.vuln_widget.show_Plugins.clearContents()
        cms_name = self.vuln_widget.show_Plugins_comboBox_cms_name.currentText()  # 获取文本
        vuln_class = self.vuln_widget.show_Plugins_comboBox_vuln_class.currentText()  # 获取文本
        if cms_name == "ALL" and vuln_class == "ALL":
            sql = "SELECT * from vuln_poc "
        elif cms_name == "ALL" and vuln_class != "ALL":
            sql = "SELECT * from vuln_poc where vuln_class='%s'" % (vuln_class)
        elif cms_name != "ALL" and vuln_class == "ALL":
            sql = "SELECT * from vuln_poc where cms_name = '%s'" % (cms_name)
        else:
            sql = "SELECT * from vuln_poc where cms_name = '%s' and vuln_class='%s'" % (cms_name, vuln_class)
        cms_data = self.sql_search(sql, 'dict')
        i = 0
        self.vuln_widget.show_Plugins.setRowCount(len(cms_data))
        self.vuln_widget.show_Plugins.setSortingEnabled(False)
        for single in cms_data:
                id = QTableWidgetItem(str(single['id']))
                cms_name = QTableWidgetItem(str(single['cms_name']))
                vuln_name = QTableWidgetItem(str(single['vuln_name']))
                vuln_class = QTableWidgetItem(str(single['vuln_class']))
                vuln_identifier = QTableWidgetItem(str(single['vuln_identifier']))
                vuln_referer = QTableWidgetItem(str(single['vuln_referer']))
                vuln_description = QTableWidgetItem(str(single['vuln_description']))
                vuln_file = QTableWidgetItem(str(single['vuln_file']))
                vuln_author = QTableWidgetItem(str(single['vuln_author']))
                vuln_solution = QTableWidgetItem(str(single['vuln_solution']))
                self.vuln_widget.show_Plugins.setItem(i, 0, id)
                self.vuln_widget.show_Plugins.setItem(i, 1, cms_name)
                self.vuln_widget.show_Plugins.setItem(i, 2, vuln_name)
                self.vuln_widget.show_Plugins.setItem(i, 3, vuln_class)
                self.vuln_widget.show_Plugins.setItem(i, 4, vuln_identifier)
                self.vuln_widget.show_Plugins.setItem(i, 5, vuln_referer)
                self.vuln_widget.show_Plugins.setItem(i, 6, vuln_description)
                self.vuln_widget.show_Plugins.setItem(i, 7, vuln_file)
                self.vuln_widget.show_Plugins.setItem(i, 8, vuln_author)
                self.vuln_widget.show_Plugins.setItem(i, 9, vuln_solution)
                i = i + 1
        self.vuln_widget.show_Plugins.setSortingEnabled(True)

    def get_dir_file(self, dir):
        all_plugins = []
        plugins_path = dir
        plugins_path = plugins_path.replace("\\", "/")
        for cms_name in os.listdir(plugins_path):  # 遍历目录名
            cms_path = os.path.join(plugins_path, cms_name).replace("\\", "/")
            for poc_file_dir, poc_dirs_list, poc_file_name_list in os.walk(cms_path):  # 遍历poc文件，得到方法名称
                # print(path,dirs,poc_methos_list)
                # print(poc_file_name_list)
                for poc_file_name in poc_file_name_list:
                    poc_name_path = poc_file_dir + "\\" + poc_file_name
                    poc_name_path = poc_name_path.replace("\\", "/")
                    # 判断是py文件在打开  文件存在
                    # print(poc_file_name[:8])
                    if os.path.isfile(poc_name_path) and poc_file_name.endswith('.py') and len(
                            poc_file_name) >= 8 and poc_file_name[:8] == "Plugins_":
                        single_plugins = {}
                        single_plugins['cms_name'] = cms_name
                        single_plugins['poc_file_name'] = poc_file_name
                        single_plugins['poc_file_path'] = poc_name_path
                        all_plugins.append(single_plugins)
        return all_plugins

    def get_domain_file(self, dir):
        all_plugins = []
        plugins_path = dir.replace("\\", "/")

        for poc_file_dir, poc_dirs_list, poc_file_name_list in os.walk(plugins_path):  # 遍历poc文件，得到方法名称
            # print(path,dirs,poc_methos_list)
            # print(poc_file_name_list)
            for poc_file_name in poc_file_name_list:
                poc_name_path = poc_file_dir + "\\" + poc_file_name
                poc_name_path = poc_name_path.replace("\\", "/")
                # 判断是py文件在打开  文件存在
                # print(poc_file_name[:8])
                if os.path.isfile(poc_name_path) and poc_file_name.endswith('.py') and len(
                        poc_file_name) >= 8 and poc_file_name[:8] == "Plugins_":
                    single_plugins = {}
                    single_plugins['poc_file_name'] = poc_file_name
                    single_plugins['poc_file_path'] = poc_name_path
                    all_plugins.append(single_plugins)
        return all_plugins

    # 重新加载插件
    def vuln_reload_Plugins(self):
        self.Ui.treeWidget_Plugins.clear()
        self.Ui.textEdit_log.setText("[%s]Start:正在重新加载插件..." % (time.strftime('%H:%M:%S', time.localtime(time.time()))))
        # 连接数据库。如果数据库不存在的话，将会自动创建一个 数据库
        conn = sqlite3.connect(DB_NAME)
        # 创建一个游标 curson
        cursor = conn.cursor()
        # 删除数据库，重新建立
        if os.path.isfile(DB_NAME):
            try:
                sql = 'drop table if exists vuln_poc;'
                cursor.execute(sql)
                self.Ui.textEdit_log.append(
                    "<a  style=\"color:green\">[%s]Success:删除数据表成功！</a>" % (
                        time.strftime('%H:%M:%S', time.localtime(time.time()))))
            except Exception as e:
                self.Ui.textEdit_log.append(
                    "<a  style=\"color:red\">[%s]Error:数据表vuln_poc删除失败！<br>[Exception]:<br>%s</a>" % (
                        (time.strftime('%H:%M:%S', time.localtime(time.time()))), e))
                return 0
        else:
            self.Ui.textEdit_log.append(
                "<a  style=\"color:black\">[%s]Info:数据库文件不存在，尝试创建数据库！</a>" % (
                    time.strftime('%H:%M:%S', time.localtime(time.time()))))
        try:

            # 执行一条语句,创建 user表 如不存在创建
            sql = 'CREATE TABLE `vuln_poc`  (`id` int(255) NULL DEFAULT NULL,`cms_name` varchar(255),`vuln_file` varchar(255),`vuln_name` varchar(255),`vuln_author` varchar(255),`vuln_referer` varchar(255),`vuln_description` varchar(255),`vuln_identifier` varchar(255),`vuln_solution` varchar(255),`ispoc` int(255) NULL DEFAULT NULL,`isexp` int(255) NULL DEFAULT NULL,`vuln_class` varchar(255),`FofaQuery_link` varchar(255),`target` varchar(1000),`FofaQuery` varchar(255))'
            # sql = 'create table IF NOT EXISTS vuln_poc ("id" integer PRIMARY KEY AUTOINCREMENT,"cms_name" varchar(30),"vuln_file" varchar(50),"vuln_name" varchar(30),"vuln_author" varchar(50),"vuln_referer" varchar(50),"vuln_description" varchar(200),"vuln_identifier" varchar(100),"vuln_solution" varchar(500),  "ispoc" integer(1),"isexp" integer(1))'
            cursor.execute(sql)
            self.Ui.textEdit_log.append(
                "<a  style=\"color:green\">[%s]Success:创建数据表完成！</a>" % (
                    time.strftime('%H:%M:%S', time.localtime(time.time()))))
        except Exception as e:
            self.Ui.textEdit_log.append(
                "<a  style=\"color:red\">[%s]Error:数据表创建失败！<br>[Exception]:<br>%s</a>" % (
                time.strftime('%H:%M:%S', time.localtime(time.time())), e))
            return 0
        try:
            id = 1
            all_plugins = self.get_dir_file(vuln_plugins_dir)
            for poc in all_plugins:
                try:
                    nnnnnnnnnnnn1 = importlib.machinery.SourceFileLoader(poc['poc_file_path'][:-3],
                                                                         poc['poc_file_path']).load_module()
                    vuln_info = nnnnnnnnnnnn1.vuln_info()
                    if vuln_info.get('vuln_class'):
                        vuln_class = vuln_info.get('vuln_class')
                    else:
                        vuln_class = '未分类'
                    if vuln_info.get('FofaQuery_link'):
                        FofaQuery_link = (vuln_info.get('FofaQuery_link'))
                    else:
                        FofaQuery_link = ''
                    if vuln_info.get('FofaQuery'):
                        FofaQuery = vuln_info.get('FofaQuery')
                    else:
                        FofaQuery = ''
                    insert_sql = 'insert into vuln_poc  (id,cms_name,vuln_file,vuln_name,vuln_author,vuln_referer,vuln_description,vuln_identifier,vuln_solution,ispoc,isexp,vuln_class,FofaQuery_link,FofaQuery,target) values (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)'

                    # 将数据插入到表中
                    cursor.execute(insert_sql, (
                        id, poc['cms_name'], poc['poc_file_name'], vuln_info['vuln_name'], vuln_info['vuln_author'],
                        vuln_info['vuln_referer'], vuln_info['vuln_description'],
                        vuln_info['vuln_identifier'], vuln_info['vuln_solution'], vuln_info['ispoc'],
                        vuln_info['isexp'], vuln_class, FofaQuery_link, FofaQuery, '[]'))
                    id = id + 1
                except Exception as  e:
                    self.Ui.textEdit_log.append(
                        "<a  style=\"color:red\">[%s]Error:%s脚本执行错误！<br>[Exception]:<br>%s</a>" % (
                            (time.strftime('%H:%M:%S', time.localtime(time.time()))), poc['poc_file_name'], e))
                    continue
                conn.commit()  # 提交
            # print(result)
            cursor.execute("select count(ispoc) from vuln_poc where ispoc =1")
            poc_num = cursor.fetchall()
            cursor.execute("select count(isexp) from vuln_poc where isexp =1")
            exp_num = cursor.fetchall()
            conn.close()
            self.Ui.textEdit_log.append(
                "<a  style=\"color:green\">[%s]Success:共写入%s个POC</a>" % (
                (time.strftime('%H:%M:%S', time.localtime(time.time()))), poc_num[0][0]))
            self.Ui.textEdit_log.append(
                "<a  style=\"color:green\">[%s]Success:共写入%s个EXP</a>" % (
                    (time.strftime('%H:%M:%S', time.localtime(time.time()))), exp_num[0][0]))

            self.load_vuln_plugins()  # 调用加载插件
            box = QtWidgets.QMessageBox()
            box.information(self, "漏洞插件", "数据更新完成！\nPOC数量：%s\nEXP数量：%s" % (poc_num[0][0], exp_num[0][0]))
            # reboot = sys.executable
            # os.execl(reboot, reboot, *sys.argv)
        except Exception as e:
                self.Ui.textEdit_log.append(
                    "<a  style=\"color:red\">[%s]Error:数据写入失败！\n[Exception]:\n%s</a>" % (
                    (time.strftime('%H:%M:%S', time.localtime(time.time()))), e))
                return 0

    def domain_reload_Plugins(self):
        self.Ui.treeWidget_domain_Plugins.clear()
        self.Ui.textEdit_doamin_log.setText(
            "[%s]Start:正在重新加载插件..." % (time.strftime('%H:%M:%S', time.localtime(time.time()))))
        # 连接数据库。如果数据库不存在的话，将会自动创建一个 数据库
        conn = sqlite3.connect(DB_NAME)
        # 创建一个游标 curson
        cursor = conn.cursor()
        # 删除数据库，重新建立
        if os.path.isfile(DB_NAME):
            try:
                sql = 'drop table if exists domain;'
                cursor.execute(sql)
                self.Ui.textEdit_doamin_log.append(
                    "<a  style=\"color:green\">[%s]Success:删除数据表成功！</a>" % (
                        time.strftime('%H:%M:%S', time.localtime(time.time()))))
            except Exception as e:
                self.Ui.textEdit_doamin_log.append(
                    "<a  style=\"color:red\">[%s]Error:数据表domain删除失败！<br>[Exception]:<br>%s</a>" % (
                        (time.strftime('%H:%M:%S', time.localtime(time.time()))), e))
                return 0
        else:
            self.Ui.textEdit_doamin_log.append(
                "<a  style=\"color:black\">[%s]Info:数据表不存在，尝试创建数据表！</a>" % (
                    time.strftime('%H:%M:%S', time.localtime(time.time()))))
        try:

            # 执行一条语句,创建 user表 如不存在创建
            sql = 'CREATE TABLE `domain`  (`id` int(255) NULL DEFAULT NULL,`plugins_file` varchar(255),`plugins_name` varchar(255),`plugins_author` varchar(255),`plugins_description` varchar(255),`plugins_key1` varchar(255),`plugins_key2` varchar(255),`plugins_key3` varchar(255))'
            cursor.execute(sql)
            self.Ui.textEdit_doamin_log.append(
                "<a  style=\"color:green\">[%s]Success:创建数据表完成！</a>" % (
                    time.strftime('%H:%M:%S', time.localtime(time.time()))))
        except Exception as e:
            self.Ui.textEdit_doamin_log.append(
                "<a  style=\"color:red\">[%s]Error:数据表创建失败！<br>[Exception]:<br>%s</a>" % (
                time.strftime('%H:%M:%S', time.localtime(time.time())), e))
            return 0
        try:
            id = 1
            all_plugins = self.get_domain_file(domain_plugins_dir)
            for poc in all_plugins:
                try:
                    nnnnnnnnnnnn1 = importlib.machinery.SourceFileLoader(poc['poc_file_path'][:-3],
                                                                         poc['poc_file_path']).load_module()
                    domain_info = nnnnnnnnnnnn1.domain_info()
                    insert_sql = 'insert into domain  (id, plugins_file, plugins_name, plugins_author, plugins_description, plugins_key1,plugins_key2, plugins_key3) values (?,?,?,?,?,?,?,?)'
                    # # 将数据插入到表中
                    cursor.execute(insert_sql, (
                    id, poc['poc_file_name'], domain_info.get('plugins_name'), domain_info.get('plugins_author'),
                    domain_info.get('plugins_description'), domain_info.get('plugins_key1'),
                    domain_info.get('plugins_key2'), domain_info.get('plugins_key3')))
                    id = id + 1
                except Exception as  e:
                    self.Ui.textEdit_doamin_log.append(
                        "<a  style=\"color:red\">[%s]Error:%s脚本执行错误！<br>[Exception]:<br>%s</a>" % (
                            (time.strftime('%H:%M:%S', time.localtime(time.time()))), poc['poc_file_name'], e))
                    continue
                conn.commit()  # 提交
            # print(result)
            cursor.execute("select count(plugins_name) from domain")
            poc_num = cursor.fetchall()
            conn.close()
            self.Ui.textEdit_doamin_log.append(
                "<a  style=\"color:green\">[%s]Success:共写入%s个插件</a>" % (
                (time.strftime('%H:%M:%S', time.localtime(time.time()))), poc_num[0][0]))
            # self.()  # 调用加载插件
            self.load_domain_plugins()
            box = QtWidgets.QMessageBox()
            box.information(self, "Load Plugins", "数据更新完成！\n子域名插件数量：%s" % (poc_num[0][0]))
            # reboot = sys.executable
            # os.execl(reboot, reboot, *sys.argv)
        except Exception as e:
                self.Ui.textEdit_doamin_log.append(
                    "<a  style=\"color:red\">[%s]Error:数据写入失败！\n[Exception]:\n%s</a>" % (
                    (time.strftime('%H:%M:%S', time.localtime(time.time()))), e))
                return 0

    def show_others(self, q):

        if q.text() == "关于软件":
            self.about()
            return
        if q.text() == "检查更新":
            self.version_update()
            return
        if q.text() == "意见反馈":
            self.ideas()
            return
        else:
            try:
                global qss_style
                filename = config_setup.get('QSS_List', q.text())
                # print(filename)
                config_setup.set("QSS_Setup", "QSS", filename)
                with open('Qss/' + filename, 'r', encoding='utf-8') as f:
                    qss_style = f.read()
                    f.close()

                MainWindows.setStyleSheet(self, qss_style)
                # python = sys.executable
                # os.execl(python, python, *sys.argv)
                self.change_pifu(q.text())

            except Exception as e:
                QMessageBox.critical(self, 'Error', str(e))
                pass

    def vuln_exp(self):
        if self.Ui.tableWidget_vuln.selectedItems():
            url = self.Ui.tableWidget_vuln.selectedItems()[0].text()
            poc_name = self.Ui.tableWidget_vuln.selectedItems()[1].text()
            sql = "select * from vuln_poc where vuln_name='%s'" % (poc_name)
            exp_data = self.sql_search(sql, 'dict')
            # print(exp_data)
            if len(exp_data):
                # 根据文本查找索引设置选中
                cms_index = self.Ui.vuln_type.findText(exp_data[0]['cms_name'], QtCore.Qt.MatchFixedString)
                if cms_index >= 0:
                    # print(2)
                    self.Ui.vuln_type.setCurrentIndex(cms_index)
                    self.change_exp_list(exp_data[0]['cms_name'])
                    exp_index = self.Ui.vuln_name.findText(exp_data[0]['vuln_name'], QtCore.Qt.MatchFixedString)
                    if cms_index >= 0:
                        self.Ui.vuln_name.setCurrentIndex(exp_index)
                    else:
                        box = QtWidgets.QMessageBox()
                        box.warning(self, "提示", "该漏洞暂时没有利用工具！")
                else:
                    box = QtWidgets.QMessageBox()
                    box.warning(self, "提示", "该漏洞暂时没有利用工具！")

                self.Ui.tabWidget.setCurrentIndex(1)
                self.Ui.vuln_lineEdit_url.setText(url)

            else:
                box = QtWidgets.QMessageBox()
                box.warning(self, "提示", "该漏洞暂时没有利用工具！")
        else:
            self.Ui.textEdit_log.append(
                "<a  style=\"color:red\">[%s]Error:请选择一个结果！</a>" % (
                    time.strftime('%H:%M:%S', time.localtime(time.time()))))
    def exp_send(self, exp_type):
        data = {}
        ip = ''
        port = 8080
        cmd = ''
        url = self.Ui.vuln_lineEdit_url.text()
        if not url:
            box = QtWidgets.QMessageBox()
            box.warning(self, "提示", "目标地址不能为空！")
            return
        if "http://" not in url and "https://" not in url:
            box = QtWidgets.QMessageBox()
            box.warning(self, "提示", "请以http://或https://开头！")
            return
        cms_name = self.Ui.vuln_type.currentText()
        exp_name = self.Ui.vuln_name.currentText()
        exp_file_name = self.sql_search(
            "select vuln_file from vuln_poc where vuln_name='%s' and cms_name='%s'" % (exp_name, cms_name))
        # print(exp_file_name)
        exp_path = vuln_plugins_dir + '/' + cms_name + '/' + exp_file_name[0][0]
        cookie = self.Ui.vuln_lineEdit_cookie.text()
        heads = self.Ui.plainTextEdit_heads.toPlainText()
        heads_dict = {}
        if cookie:
            heads_dict['Cookie'] = cookie
        heads = heads.splitlines()
        for head in heads:
            head = head.split(':')
            heads_dict[head[0].strip()] = head[1].strip()

        if exp_type == 'cmd':
            command = self.Ui.vuln_exp_input_cmd.text()
            self.Ui.vuln_exp_textEdit_log.append(
                "[%s]命令执行:%s" % ((time.strftime('%H:%M:%S', time.localtime(time.time()))), command))
            data['type']='cmd'
            data['command'] = command

        elif exp_type == 'shell':
            data['type'] = 'shell'
            ip = self.Ui.vuln_exp_input_ip.text()
            port = self.Ui.vuln_exp_input_port.text()
            data['reverse_ip']=ip
            data['reverse_port']=port
            if not re.match(
                    r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$",
                    ip):
                box = QtWidgets.QMessageBox()
                box.warning(self, "提示", "请输入合法的IP地址！")
                return
            try:
                if port == '' or int(port) not in range(1, 65535):
                    box = QtWidgets.QMessageBox()
                    box.warning(self, "提示", "请输入合法的端口！")
                    return
            except Exception as e:
                self.__Logger.error(str(e)+'----'+str(e.__traceback__.tb_lineno)+'行')
                box = QtWidgets.QMessageBox()
                box.warning(self, "提示", "请输入合法的端口！")
                return
            self.Ui.vuln_exp_textEdit_log.append(
                "[%s]反弹Shell:%s:%s" % ((time.strftime('%H:%M:%S', time.localtime(time.time()))), ip, port))
        elif exp_type == 'uploadfile':
            filename = self.Ui.vuln_exp_lineEdit_filename.text()
            shell_neirong  =self.Ui.vuln_exp_textEdit_shell.toPlainText()
            data['type'] = 'uploadfile'
            data['filename'] = filename
            data['filename_contents'] = shell_neirong

        self.exp_send_obj = Vuln_Exp(exp_path, url, heads_dict, data)  # 创建一个线程
        self.exp_send_obj._data.connect(self.update_data_exp)  # 线程发过来的信号挂接到槽函数update_sum
        self.Ui.vuln_exp_button_shell.setEnabled(False)
        self.Ui.vuln_exp_button_cmd.setEnabled(False)
        self.exp_send_obj.start()  # 线程启动


    def update_data_exp(self, result):
        if result.get('Result'):
            self.vuln_exp_log("Result", True, result.get("Result_Info"))
        # 不存在
        else:
            self.vuln_exp_log("Result", False, result.get("Result_Info"))
        if result.get('Error_Info'):
            self.vuln_exp_log("Error", False, result.get("Error_Info"))
        if result.get('Debug_Info'):
            self.vuln_exp_log("Debug", False, result.get("Debug_Info"))
        self.Ui.vuln_exp_button_shell.setEnabled(True)  # 让按钮恢复可点击状态
        self.Ui.vuln_exp_button_cmd.setEnabled(True)  # 让按钮恢复可点击状态

    # 关于
    def about(self):
        box = QtWidgets.QMessageBox()
        # box.setIcon()
        box.about(self, "About",
                  "\t\t\tAbout\n       此程序为一款专为渗透测试人员开发的测试工具，请勿非法使用！\n\t\t\t   Powered by qianxiao996")

    # 更新
    def version_update(self):
        response = requests.get("https://qianxiao996.cn/Emperor/version.txt", timeout=3)
        if (int(response.text.replace('.', '')) > int(version.replace('.', ''))):
            reply = QMessageBox.question(window, '软件更新',
                                         "当前版本：%s\n最新版本：%s\n检测到软件已发布新版本，是否前去下载?" % (version, response.text),
                                         QMessageBox.Yes | QMessageBox.No,
                                         QMessageBox.Yes)
            if reply == QMessageBox.Yes:
                webbrowser.open('https://github.com/qianxiao996/Emperor/releases')
            else:
                pass
        else:
            box = QtWidgets.QMessageBox()
            box.information(self, "软件更新", "当前版本：%s\n最新版本：%s\n已是最新版本" % (version, response.text))

    # 意见反馈
    def ideas(self):
        box = QtWidgets.QMessageBox()
        box.setIcon(1)
        box.about(self, "意见反馈", "作者邮箱：qianxiao996@126.com\n作者主页：http://qianxiao996.cn")

    # 全选
    def vuln_all(self):
        item = QtWidgets.QTreeWidgetItemIterator(self.Ui.treeWidget_Plugins)
        # 该类的value()即为QTreeWidgetItem
        while item.value():
            if item.value().checkState(0) != QtCore.Qt.Checked:
                item.value().setCheckState(0, QtCore.Qt.Checked)
            item = item.__iadd__(1)

    def domain_all(self):
        item = QtWidgets.QTreeWidgetItemIterator(self.Ui.treeWidget_domain_Plugins)
        # 该类的value()即为QTreeWidgetItem
        while item.value():
            if item.value().checkState(0) != QtCore.Qt.Checked:
                item.value().setCheckState(0, QtCore.Qt.Checked)
            item = item.__iadd__(1)

    # 反选
    def vuln_noall(self):
        item = QtWidgets.QTreeWidgetItemIterator(self.Ui.treeWidget_Plugins)
        # 该类的value()即为QTreeWidgetItem
        while item.value():
            if item.value().checkState(0) == QtCore.Qt.Checked:
                item.value().setCheckState(0, QtCore.Qt.Unchecked)
            item = item.__iadd__(1)

    def domain_noall(self):
        item = QtWidgets.QTreeWidgetItemIterator(self.Ui.treeWidget_domain_Plugins)
        # 该类的value()即为QTreeWidgetItem
        while item.value():
            if item.value().checkState(0) == QtCore.Qt.Checked:
                item.value().setCheckState(0, QtCore.Qt.Unchecked)
            item = item.__iadd__(1)

    # 文件打开对话框
    def file_open(self, type):
        fileName, selectedFilter = QFileDialog.getOpenFileName(self, (r"上传文件"), '', type)
        return (fileName)  # 返回文件路径

    # 保存文件对话框
    def file_save(self, filename):
        fileName, filetype = QFileDialog.getSaveFileName(self, (r"保存文件"), (filename), r"All files(*.*)")
        return fileName



    def vuln_exp_log(self, type, flag=False, Info=''):
        if type == "Error":
            self.Ui.vuln_exp_textEdit_log.append(
                "<a  style=\"color:red\">[%s]Error:<br>Error-Info:%s。</a>" % (
                    time.strftime('%H:%M:%S'), Info))
        elif type == "Debug" and self.Ui.vuln_exp_debug.isChecked():
            self.Ui.vuln_exp_textEdit_log.append(
                "<a  style=\"color:blue\">[%s]Debug:<br>Debug-Info:%s。</a>" % (
                    time.strftime('%H:%M:%S'), Info))

        # print(r)
        elif type == 'Result' and flag:
            self.Ui.textEdit_result.setText(Info)
            self.Ui.vuln_exp_textEdit_log.append(
                "[%s]执行结果:%s" % (time.strftime('%H:%M:%S'), Info))
        elif type == 'Result' and not flag:
                self.Ui.vuln_exp_textEdit_log.append(
                    "<a  style=\"color:black\">[%s]%s:%s。</a>" % (time.strftime('%H:%M:%S'), "Result", "执行失败"))
    def sql_search(self, sql, type='list'):
        if type == 'dict':
            conn = sqlite3.connect(DB_NAME)
            conn.row_factory = self.dict_factory
        else:
            conn = sqlite3.connect(DB_NAME)
        # 创建一个游标 curson
        cursor = conn.cursor()
        # self.Ui.textEdit_log.append("[%s]Info:正在查询数据..."%(time.strftime('%H:%M:%S', time.localtime(time.time()))))
        # 列出所有数据
        cursor.execute(sql)
        if type in ["delete","update","insert"]:
            conn.commit()
            return True
        values = cursor.fetchall()
        return values

    # sql查询返回字典
    def dict_factory(self, cursor, row):
        d = {}
        for idx, col in enumerate(cursor.description):
            d[col[0]] = row[idx]
        return d

    def change_exp_list(self, exp_cms_name):
        self.Ui.vuln_name.clear()
        for exp_methods in self.exp_cms_name_dict[exp_cms_name]:
            # print(exp_methods)
            self.Ui.vuln_name.addItem(exp_methods['vuln_name'])

        # self.change_exp_name_change()
        # print(exp_cms_name)

    # vuln_name 改变调用函数
    def change_exp_name_change(self):
        self.Ui.exp_tabWidget.setCurrentIndex(0)
        vuln_name_text = self.Ui.vuln_name.currentText()
        sql = "select * from vuln_poc where vuln_name='%s'" % vuln_name_text
        vuln_data = self.sql_search(sql, 'dict')[0]
        # print(expdescription[0][0])
        # pass
        if vuln_data:
            if vuln_data.get('isexp'):
                vuln_exp = 'True'
            else:
                vuln_exp = 'False'
            if vuln_data.get('ispoc'):
                vuln_poc = 'True'
            else:
                vuln_poc = 'False'

            data = "漏洞名称：" + str(vuln_data.get('vuln_name')) + "\n漏洞编号：" + str(
                vuln_data.get('vuln_identifier')) + "\n漏洞分类：" + str(vuln_data.get('vuln_class')) + "\n资产分类：" + str(
                vuln_data.get('cms_name')) + "\n漏洞来源：" + str(vuln_data.get('vuln_referer')) + "\n插件作者：" + str(
                vuln_data.get('vuln_author')) + "\n插件位置：" + vuln_plugins_dir + "/" + str(
                vuln_data.get('cms_name')) + "/" + str(
                vuln_data.get('vuln_file')) + "\n是否有POC：" + vuln_poc + "\n是否有EXP：" + vuln_exp + "\n漏洞描述：" + str(
                vuln_data.get('vuln_description')) + "\n修复建议：" + str(vuln_data.get('vuln_solution'))
            self.Ui.vuln_exp_textEdit_info.setText(data)
        else:
            box = QtWidgets.QMessageBox()
            box.warning(self, "提示", "该EXP暂无描述信息！")

    def closeEvent(self, event):
        """
        重写closeEvent方法，实现dialog窗体关闭时执行一些代码
        :param event: close()触发的事件
        :return: None
        """
        reply = QtWidgets.QMessageBox.question(self,
                                               '本程序',
                                               "是否要退出程序？",
                                               QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No,
                                               QtWidgets.QMessageBox.No)
        if reply == QtWidgets.QMessageBox.Yes:
            config_setup.write(open(config_file_dir, "r+", encoding="utf-8"))  # r+模式
            event.accept()
        else:
            event.ignore()

    def check_update(self):
        try:
            response = requests.get("https://qianxiao996.cn/Emperor/version.txt", timeout=3)
            if (int(response.text.replace('.', '')) > int(version.replace('.', ''))):
                reply = QtWidgets.QMessageBox.question(self,
                                                       '软件更新',
                                                       "检测到软件已发布新版本，是否前去下载?",
                                                       QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No,
                                                       QtWidgets.QMessageBox.No)
                if reply == QtWidgets.QMessageBox.Yes:
                    webbrowser.open('https://github.com/qianxiao996/Emperor/releases')
                else:
                    pass
        except Exception as e:
            pass

    def alert_web(self,url):
        # print(url)/
        if ("http://" not in url) and ("https://" not in url):
            url = "http://"+url
        alert_web_form = QtWidgets.QMainWindow(self)
        alert_web_form.setStyleSheet(qss_style)
        alert_web_form.setWindowTitle('Emperor内置浏览器')
        browser = QWebEngineView()
        browser.setGeometry(QtCore.QRect(5, 30, 1355, 730))  # (50 左边, 50 右边, 700 宽, 500 高)
        # self.browser.page().fullScreenRequested.connect(self._fullScreenRequested)
        browser.load(QUrl(url))
        alert_web_form.setCentralWidget(browser)
        alert_web_form.show()
        self.center(alert_web_form)
    def center(self,alert_web_form):
        qr = alert_web_form.frameGeometry()
        cp = QDesktopWidget().availableGeometry().center()
        qr.moveCenter(cp)
        alert_web_form.move(qr.topLeft())


    def alert_portscan(self):
        if self.Ui.portscan_result.selectedItems()[2].text() in ["HTTP","HTTPS","http","https"]:
            url = self.Ui.portscan_result.selectedItems()[2].text().lower()+"://"+self.Ui.portscan_result.selectedItems()[0].text().strip()+":"+self.Ui.portscan_result.selectedItems()[1].text().strip()
            # print(url)
        else:
            url = "http://"+self.Ui.portscan_result.selectedItems()[0].text()+":"+self.Ui.portscan_result.selectedItems()[1].text()

        self.alert_web(url)

    def get_title_start(self):
        try:
            timeout = int(self.Ui.comboBox_gettitle_timeout.currentText())  # 获取文本
        except:
            box = QtWidgets.QMessageBox()
            box.warning(self, "提示", "请输入正确的超时时间")
            return
        try:
            threads = int(self.Ui.comboBox_gettitle_threadsnum.currentText())  # 获取文本
        except:

            box = QtWidgets.QMessageBox()
            box.warning(self, "提示", "请输入正确的线程数量")
            return
        url_text = self.Ui.plainTextEdit_gettitle_url.toPlainText()
        checkBox_302 = self.Ui.checkBox_302.isChecked()
        chrome_driver=''
        if self.Ui.checkBox_screen.isChecked():
            for key, value in config_setup.items('Chrome'):
                if value == config_setup.get('Chrome', 'Chrome_path'):
                    chrome_driver = value
                    break
        self.gettitle_obj = Get_Title(self.__Logger,url_text,threads, timeout,checkBox_302,chrome_driver)
        self.gettitle_obj._data.connect(self.update_gettitle_data)  # 线程发过来的信号挂接到槽函数update_sum
        self.gettitle_obj._num.connect(self.update_gettitle_num)  # 线程发过来的信号挂接到槽函数update_sum
        self.gettitle_obj._count.connect(self.update_gettitle_num_count)  # 线程发过来的信号挂接到槽函数update_sum
        self.gettitle_obj._log.connect(self.update_gettitle_log)  # 线程发过来的信号挂接到槽函数update_sum
        self.Ui.pushButton_gettitle_start.setEnabled(False)
        self.Ui.pushButton_gettitle_stop.setEnabled(True)
        self.Ui.progressBar_gettitle.setValue(0)
        self.Ui.plainTextEdit_gettitle_log.clear()
        self.gettitle_obj.start()  # 线程启动
    def update_gettitle_data(self,data):

        # self.gettitle_lock.acquire()

        if len(self.appand_gettitle_data)<=10 and not data.get('end'):
            self.appand_gettitle_data.append(data)

        else:
            #防止界面卡顿
            appand = self.appand_gettitle_data
            self.appand_gettitle_data=[]
            for data in appand:
                self.Ui.tableWidget_gettitle_result.setSortingEnabled(False)

                row = self.Ui.tableWidget_gettitle_result.rowCount()  # 获取行数
                self.Ui.tableWidget_gettitle_result.setRowCount(row + 1)
                portscan_Url = QTableWidgetItem(data.get('Url'))
                portscan_Ip = QTableWidgetItem(data.get('Ip'))
                portscan_Title = QTableWidgetItem(data.get('Title'))
                portscan_Server = QTableWidgetItem(data.get("Server"))
                portscan_Banner = QTableWidgetItem(data.get('Banner'))
                portscan_screen_img = QTableWidgetItem(data.get('screen_img'))

                self.Ui.tableWidget_gettitle_result.setItem(row, 0, portscan_Url)
                self.Ui.tableWidget_gettitle_result.setItem(row, 1, portscan_Ip)
                self.Ui.tableWidget_gettitle_result.setItem(row, 2, portscan_Title)
                self.Ui.tableWidget_gettitle_result.setItem(row, 3, portscan_Server)
                self.Ui.tableWidget_gettitle_result.setItem(row, 4, portscan_Banner)
                self.Ui.tableWidget_gettitle_result.setItem(row, 5, portscan_screen_img)
            #自动调节列宽度
            self.Ui.tableWidget_gettitle_result.setVisible(False)
            # self.Ui.tableWidget_gettitle_result.resizeColumnsToContents()
            self.Ui.tableWidget_gettitle_result.resizeColumnToContents(0)
            self.Ui.tableWidget_gettitle_result.setVisible(True)
            self.Ui.tableWidget_gettitle_result.setSortingEnabled(True)
        # self.gettitle_lock.release()

    def update_gettitle_num(self,num):
        step = self.Ui.progressBar_gettitle.value()
        # num = int(self.Ui.portscan_num_go.text())
        # self.Ui.portscan_num_go.setText(str(num + 1))
        self.Ui.progressBar_gettitle.setValue(step+num)

    def update_gettitle_num_count(self,count):
        self.Ui.progressBar_gettitle.setMaximum(count)
    def update_gettitle_log(self,log):
        self.Ui.plainTextEdit_gettitle_log.appendPlainText("[%s] %s"%(time.strftime('%H:%M:%S'),log))
        if log =="停止扫描" or log=="扫描结束":
                self.Ui.pushButton_gettitle_start.setEnabled(True)
                self.Ui.pushButton_gettitle_stop.setEnabled(False)
    def get_title_stop(self):
        self.Ui.plainTextEdit_gettitle_log.appendPlainText("发出停止信号，请等待...")
        self.gettitle_obj.gettitle_Queue.queue.clear()
        self.gettitle_obj.stop_flag = 1
            # self.Ui.progressBar_portscan.setValue(100)


    def change_gettitle_data(self):
        #端口扫描点击行显示数据包及预览
        row = self.Ui.tableWidget_gettitle_result.selectedItems()[0].row()
        url  = self.Ui.tableWidget_gettitle_result.item(row,0).text()
        Banner  = self.Ui.tableWidget_gettitle_result.item(row,4).text()
        try:
            imgsrc = self.Ui.tableWidget_gettitle_result.item(row,5).text()
            # imgsrc = ""
            if imgsrc:
                qrPixmap = QPixmap(QImage.fromData(base64.b64decode(imgsrc))).scaled(self.Ui.browser_gettitle.width(), self.Ui.browser_gettitle.height())
                self.Ui.browser_gettitle.setPixmap(qrPixmap)
            else:
                self.Ui.browser_gettitle.setText("没有截图")
        except:
            self.Ui.browser_gettitle.setText("截图加载失败")

        self.Ui.plainTextEdit_gettitle_html.setPlainText(Banner)
        # self.Ui.portscan_result_text.setHtml(banner)
        # http_list  = ["HTTP", "HTTPS", "http", "https"]
        # if any(key in url for key in http_list):
        #     pass
        #     # print("包含哦!")
        #
        # else:
        #     url = "http://" + url
        # # print(url)
        # self.Ui.browser_gettitle.load(QUrl(url))

    def change_morenpasswd_click_value(self):
        itemname =self.Ui.listWidget_morenpasswd_list.selectedItems()[0].text()
        sql_poc = "SELECT distinct * from passwd where type ='"+itemname+"'"
        passwd_list = self.sql_search(sql_poc, 'dict')
        self.set_morenpasswd_table_value(passwd_list)
        self.morenpasswd_get_name_passwd()
    def set_morenpasswd_table_value(self,passwd_list):
        self.Clear_tableWidget(self.Ui.tableWidget_morenpasswd_result)
        #排序先关闭再打开 防止为空
        self.Ui.tableWidget_morenpasswd_result.setSortingEnabled(False)
        for value in passwd_list:
            row = self.Ui.tableWidget_morenpasswd_result.rowCount()  # 获取行数
            self.Ui.tableWidget_morenpasswd_result.setRowCount(row + 1)
            passwd_id = QTableWidgetItem(value.get('id'))
            passwd_type = QTableWidgetItem(value.get("type"))
            passwd_name = QTableWidgetItem(value.get('name'))
            passwd_passwd = QTableWidgetItem(value.get('passwd'))
            self.Ui.tableWidget_morenpasswd_result.setItem(row, 0, passwd_id)
            self.Ui.tableWidget_morenpasswd_result.setItem(row, 1, passwd_type)
            self.Ui.tableWidget_morenpasswd_result.setItem(row, 2, passwd_name)
            self.Ui.tableWidget_morenpasswd_result.setItem(row, 3, passwd_passwd)
            # 自动调节列宽度
        self.Ui.tableWidget_morenpasswd_result.setSortingEnabled(True)

        # self.Ui.tableWidget_morenpasswd_result.setVisible(False)
        # self.Ui.tableWidget_morenpasswd_result.resizeColumnsToContents()
        # self.Ui.tableWidget_morenpasswd_result.setVisible(True)
    #
    def morenpasswd_get_name_passwd(self):
        self.Ui.textEdit_morenpasswd_username.clear()
        self.Ui.textEdit_morenpasswd_passwd.clear()
        name = []
        passwd = []
        for j in range(0, self.Ui.tableWidget_morenpasswd_result.rowCount()):  # 循环列
            tmp_name = self.Ui.tableWidget_morenpasswd_result.item(j, 2)
            tmp_passwd = self.Ui.tableWidget_morenpasswd_result.item(j, 3)
            if tmp_name != None and tmp_name.text() not in name:  # 有数据
                name.append(tmp_name.text())
                self.Ui.textEdit_morenpasswd_username.append(tmp_name.text())
            if tmp_passwd != None  and tmp_passwd.text() not in passwd:  # 有数据
                passwd.append(tmp_passwd.text())
                self.Ui.textEdit_morenpasswd_passwd.append(tmp_passwd.text())
    def morenpasswd_start(self):
        type =self.Ui.lineEdit_select_data.text()
        sql_poc = "SELECT distinct * from passwd where type like '%" + type+ "%'"
        passwd_list = self.sql_search(sql_poc, 'dict')
        self.set_morenpasswd_table_value(passwd_list)
        self.morenpasswd_get_name_passwd()
    def sharuanchaxun_start(self):
        res_text =self.Ui.textEdit_sharuanchaxun_res.toPlainText()
        if res_text=='':
            self.Ui.textEdit_sharuanchaxun_result.append("请输入数据！")
            return
        re_data_list = re.findall(r'(\w+)\.exe',res_text)
        sql_poc = "SELECT distinct * from av where av_name !=''"
        av_data_dict = self.sql_search(sql_poc,'dict')
        self.Ui.textEdit_sharuanchaxun_result.clear()
        result=[]
        for exe in re_data_list:
            for av_exe in av_data_dict:
                if exe+'.exe' == av_exe['av_exe']:
                    result.append(av_exe['av_name'])
                    self.Ui.textEdit_sharuanchaxun_result.append(av_exe['av_exe']+"----"+av_exe['av_name'])
        if len(result)==0:
            self.Ui.textEdit_sharuanchaxun_result.append("未查询到杀软信息！")
        # self.set_morenpasswd_table_value(passwd_list)
    def load_dir_plugins(self):
        for root, dirs, files in os.walk(dirscan_plugins_dir):
            for file in files:
                if file[-4:] == ".ini":
                    item = QListWidgetItem()
                    item.setText(file)
                    item.setCheckState(QtCore.Qt.Checked)
                    self.Ui.listWidget_dir_dict.addItem(item)
    def dir_check_all(self):
        count = self.Ui.listWidget_dir_dict.count()
        # 遍历listwidget中的内容
        for i in range(count):
            self.Ui.listWidget_dir_dict.item(i).setCheckState(QtCore.Qt.Checked)
    def dir_check_no(self):
        count = self.Ui.listWidget_dir_dict.count()
        # 遍历listwidget中的内容
        for i in range(count):
            self.Ui.listWidget_dir_dict.item(i).setCheckState(QtCore.Qt.Unchecked)

    def tools(self,type):
        tools_source = self.Ui.tools_source.toPlainText()
        if tools_source:
            self.tools_obj = Tools_Start(tools_source,type )  # 创建一个线程
            self.tools_obj._data.connect(self.update_data_tools)  # 线程发过来的信号挂接到槽函数update_sum
            self.Ui.tools_result.clear()
            self.tools_obj.start()  # 线程启动

    def fingerprint_start(self):
        checkBox_keyword = self.Ui.checkBox_fingerprint_str.isChecked()
        checkBox_fofa = self.Ui.checkBox_fingerprint_fofa.isChecked()
        timeout = int(self.Ui.comboBox_fingerprint_timeout.currentText())
        threads = int(self.Ui.comboBox_fingerprint_threads.currentText())
        methods = self.Ui.comboBox_fingerprint_methods.currentText()
        content_type = self.Ui.comboBox_fingerprint_type.currentText()
        url_text = self.Ui.plainTextEdit_fingerprint_url.toPlainText()
        if not url_text:
            box = QtWidgets.QMessageBox()
            box.warning(self, "错误", "请输入一个URL地址！")
            return

        self.fingerprint_obj = Fingerprint_Start(self,url_text, threads, timeout, checkBox_keyword,checkBox_fofa,methods,content_type)
        self.fingerprint_obj._data.connect(self.update_fingerprint_data)  # 线程发过来的信号挂接到槽函数update_sum
        self.fingerprint_obj._num.connect(self.update_fingerprint_num)  # 线程发过来的信号挂接到槽函数update_sum
        self.fingerprint_obj._count.connect(self.update_fingerprint_num_count)  # 线程发过来的信号挂接到槽函数update_sum
        self.fingerprint_obj._log.connect(self.update_fingerprint_log)  # 线程发过来的信号挂接到槽函数update_sum
        self.Ui.pushButton_fingerprint_start.setEnabled(False)
        self.Ui.pushButton_fingerprint_exit.setEnabled(True)
        self.Ui.progressBar_fingerprint.setValue(0)
        self.Ui.textEdit_fingerprint_logs.clear()
        self.fingerprint_obj.start()  # 线程启动

    def update_fingerprint_data(self,data):
        if  data.get('end'):
            self.Ui.textEdit_fingerprint_logs.append("[%s] %s"%(time.strftime('%H:%M:%S'),"扫描结束"))
            self.Ui.pushButton_fingerprint_start.setEnabled(True)
            self.Ui.pushButton_fingerprint_exit.setEnabled(False)
            return
        else:
            # data = {"Type": type, "Url": url, "Name": name, "Title": title, "Server": Server}
            self.Ui.tableWidget_gettitle_result.setSortingEnabled(False)
            row = self.Ui.tableWidget_fingerprint_result.rowCount()  # 获取行数
            self.Ui.tableWidget_fingerprint_result.setRowCount(row + 1)
            portscan_Url = QTableWidgetItem(data.get('Url'))
            portscan_Title = QTableWidgetItem(data.get('Title'))
            portscan_Name = QTableWidgetItem(data.get('Name'))
            portscan_Server = QTableWidgetItem(data.get("Server"))
            portscan_Type = QTableWidgetItem(data.get('Type'))
            self.Ui.tableWidget_fingerprint_result.setItem(row, 0, portscan_Url)
            self.Ui.tableWidget_fingerprint_result.setItem(row, 1, portscan_Title)
            self.Ui.tableWidget_fingerprint_result.setItem(row, 2, portscan_Name)
            self.Ui.tableWidget_fingerprint_result.setItem(row, 3, portscan_Server)
            self.Ui.tableWidget_fingerprint_result.setItem(row, 4, portscan_Type)

            #自动调节列宽度
            self.Ui.tableWidget_fingerprint_result.setVisible(False)
            # self.Ui.tableWidget_gettitle_result.resizeColumnsToContents()
            self.Ui.tableWidget_fingerprint_result.resizeColumnToContents(0)
            self.Ui.tableWidget_fingerprint_result.setVisible(True)
            self.Ui.tableWidget_fingerprint_result.setSortingEnabled(True)
            # self.gettitle_lock.release()

    def update_fingerprint_num(self,num):
        step = self.Ui.progressBar_fingerprint.value()
        # num = int(self.Ui.portscan_num_go.text())
        # self.Ui.portscan_num_go.setText(str(num + 1))
        self.Ui.progressBar_fingerprint.setValue(step+num)

    def update_fingerprint_num_count(self,count):
        self.Ui.progressBar_fingerprint.setMaximum(count)
    def update_fingerprint_log(self,log):
        self.Ui.textEdit_fingerprint_logs.append("[%s] %s"%(time.strftime('%H:%M:%S'),log))
        if log =="停止扫描" or log=="扫描结束":
                self.Ui.pushButton_fingerprint_start.setEnabled(True)
                self.Ui.pushButton_fingerprint_exit.setEnabled(False)
    def fingerprint_stop(self):
        self.Ui.textEdit_fingerprint_logs.setText("[%s] 发出停止信号，请等待..."%(time.strftime('%H:%M:%S')))
        self.fingerprint_obj.Fingerprint_Queue.queue.clear()
        self.fingerprint_obj.stop_flag = 1
        self.Ui.pushButton_fingerprint_start.setEnabled(True)
        self.Ui.pushButton_fingerprint_exit.setEnabled(False)
    def change_passwd_brute_dict(self):
        if self.Ui.checkBox_passwd_brute_moren_dict.isChecked():
            self.Ui.lineEdit_passwd_brute_username.setEnabled(False)
            self.Ui.lineEdit_passwd_brute_passwd.setEnabled(False)
            self.Ui.pushButton_passwd_brute_username.setEnabled(False)
            self.Ui.pushButton_passwd_brute_passwd.setEnabled(False)

        if not self.Ui.checkBox_passwd_brute_moren_dict.isChecked():
            self.Ui.lineEdit_passwd_brute_username.setEnabled(True)
            self.Ui.lineEdit_passwd_brute_passwd.setEnabled(True)
            self.Ui.pushButton_passwd_brute_username.setEnabled(True)
            self.Ui.pushButton_passwd_brute_passwd.setEnabled(True)

    def passwd_brute_setting(self):
        self.WChild_passwd_brute = Ui_TableWidget()
        self.dialog_passwd_nrute = QtWidgets.QDialog(self)
        self.WChild_passwd_brute.setupUi(self.dialog_passwd_nrute)
        self.dialog_passwd_nrute.setWindowIcon(QtGui.QIcon('Conf/main.png'))
        self.dialog_passwd_nrute.setWindowTitle("密码破解设置")
        self.dialog_passwd_nrute.show()
        sql_poc = "SELECT * from passwd_brute"
        data = self.sql_search(sql_poc, 'dict')
        self.WChild_passwd_brute.tableWidget_result.setSortingEnabled(False)
        self.WChild_passwd_brute.tableWidget_result.setColumnCount(5)
        self.WChild_passwd_brute.tableWidget_result.setHorizontalHeaderLabels(['id', '服务', '端口', '用户名','密码'])
        for i in data:
            row = self.WChild_passwd_brute.tableWidget_result.rowCount()  # 获取行数
            self.WChild_passwd_brute.tableWidget_result.setRowCount(row + 1)
            idItem = QTableWidgetItem(i.get('id'))
            ServiceItem = QTableWidgetItem(i.get('Service'))
            PortItem = QTableWidgetItem(i.get('Port'))
            UsernameItem = QTableWidgetItem(i.get('Username'))
            PasswordItem = QTableWidgetItem(i.get('Password'))
            self.WChild_passwd_brute.tableWidget_result.setItem(row, 0, idItem)
            self.WChild_passwd_brute.tableWidget_result.setItem(row, 1, ServiceItem)
            self.WChild_passwd_brute.tableWidget_result.setItem(row, 2, PortItem)
            self.WChild_passwd_brute.tableWidget_result.setItem(row, 3, UsernameItem)
            self.WChild_passwd_brute.tableWidget_result.setItem(row, 4, PasswordItem)

        self.WChild_passwd_brute.tableWidget_result.setVisible(False)
        self.WChild_passwd_brute.tableWidget_result.resizeColumnToContents(0)
        self.WChild_passwd_brute.tableWidget_result.setVisible(True)
        self.WChild_passwd_brute.tableWidget_result.setSortingEnabled(True)
        self.WChild_passwd_brute.pushButton_save.clicked.connect(self.save_passwd_brute)
    def save_passwd_brute(self):
        conn = sqlite3.connect(DB_NAME)
        # 创建一个游标 curson
        cursor = conn.cursor()
        try:
            sql = 'drop table if exists passwd_brute;'
            cursor.execute(sql)
        except Exception as e:
            self.__Logger.error(str(e))
            self.Ui.plainTextEdit_log_log.appendPlainText(str(e))
            box = QtWidgets.QMessageBox()
            box.warning(self, "错误", "数据表删除失败,请查看日志！")
            return 0

        try:
            # 执行一条语句,创建 user表 如不存在创建
            sql = 'CREATE TABLE "passwd_brute" ("id" text NOT NULL,  "Service" TEXT,  "Port" TEXT, "Username" TEXT,"Password" TEXT,PRIMARY KEY ("id"));'
            # sql = 'create table IF NOT EXISTS vuln_poc ("id" integer PRIMARY KEY AUTOINCREMENT,"cms_name" varchar(30),"vuln_file" varchar(50),"vuln_name" varchar(30),"vuln_author" varchar(50),"vuln_referer" varchar(50),"vuln_description" varchar(200),"vuln_identifier" varchar(100),"vuln_solution" varchar(500),  "ispoc" integer(1),"isexp" integer(1))'
            cursor.execute(sql)
            data=[]

            insert_sql = 'insert into passwd_brute(id,Service,Port,Username,Password) values (?,?,?,?,?)'
            for i in range(0, self.WChild_passwd_brute.tableWidget_result.rowCount()):  # 循环行
                for j in range(0, self.WChild_passwd_brute.tableWidget_result.columnCount()):  # 循环列
                    data.append(self.WChild_passwd_brute.tableWidget_result.item(i, j).text())  # 空格分隔
                cursor.execute(insert_sql, (data[0],data[1],data[2],data[3],data[4]))
                data = []
            conn.commit()  # 提交
            self.dialog_passwd_nrute.close()
            box = QtWidgets.QMessageBox()
            box.warning(self, "Success", "保存成功！")
        except Exception as e:
            self.__Logger.error(str(e))
            self.Ui.plainTextEdit_log_log.appendPlainText(str(e))
            box = QtWidgets.QMessageBox()
            box.warning(self, "Success", "保存失败,请查看日志！")
            return 0
    def update_data_tools(self,data):
        self.Ui.tools_result.appendPlainText(data)

    def passwd_brute_start(self):
        ip =  self.Ui.lineEdit_passwd_brute_ip.text()
        username =  self.Ui.lineEdit_passwd_brute_username.text()
        passwd =  self.Ui.lineEdit_passwd_brute_passwd.text()
        moren_dict = self.Ui.checkBox_passwd_brute_moren_dict.isChecked()
        scan_port = self.Ui.checkBox_passwd_brute_scanner_port.isChecked()
        one_user = self.Ui.checkBox_passwd_brute_zhanghu_one.isChecked()
        timeout = int(self.Ui.comboBox_passwd_brute_timeout.currentText())
        threads = int(self.Ui.comboBox_passwd_brute_threads.currentText())
        service_list = self.get_methods_passwd_brute()
        # print(service_list)
        self.Passwd_Brute_obj = Passwd_Brute(self,self.__Logger,ip, username, passwd, moren_dict,scan_port,one_user,timeout,threads,service_list)  # 创建一个线程
        self.Passwd_Brute_obj._log_data.connect(self.update_data_passwd_brute_log)  # update_data_passwd_brute
        self.Passwd_Brute_obj._data.connect(self.update_data_passwd_brute)  # update_data_passwd_brute
        self.Passwd_Brute_obj._max.connect(self.update_data_passwd_brute_maxvalue)
        self.Passwd_Brute_obj._count.connect(self.update_data_passwd_brute_count)  # update_data_passwd_brute
        self.Ui.pushButton_passwd_brute_stop.setEnabled(True)
        self.Ui.textEdit_passwd_brute_logs.clear()
        self.Ui.progressBar_passwd_brute_jindu.setValue(0)
        self.Ui.pushButton_passwd_brute_start.setEnabled(False)
        self.Passwd_Brute_obj.start()  # 线程启动
    def update_data_passwd_brute_log(self,data):
        if data=="扫描结束":
            self.Ui.pushButton_passwd_brute_start.setEnabled(True)
            self.Ui.pushButton_passwd_brute_stop.setEnabled(False)
        self.Ui.textEdit_passwd_brute_logs.append("[%s]%s" % ((time.strftime('%H:%M:%S', time.localtime(time.time()))), data))  # 计算结果完成后，发送结果
    def update_data_passwd_brute_maxvalue(self,num):
        self.Ui.progressBar_passwd_brute_jindu.setMaximum(num)
        self.Ui.progressBar_passwd_brute_jindu.setValue(0)
    def update_data_passwd_brute_count(self,num):

        step = self.Ui.progressBar_passwd_brute_jindu.value()
        # num = int(self.Ui.portscan_num_go.text())
        # self.Ui.portscan_num_go.setText(str(num + 1))
        # print(step+num)
        self.Ui.progressBar_passwd_brute_jindu.setValue(step+num)
    def update_data_passwd_brute(self,data):
        # print(data)
        row = self.Ui.tableWidget_passwd_brute_result.rowCount()  # 获取行数
        self.Ui.tableWidget_passwd_brute_result.setRowCount(row + 1)
        passwd_brute_ip = QTableWidgetItem(data.get('ip'))
        passwd_brute_port = QTableWidgetItem(data.get('port'))
        passwd_brute_service = QTableWidgetItem(data.get('service'))
        passwd_brute_user = QTableWidgetItem(data.get('user'))
        passwd_brute_pass = QTableWidgetItem(data.get('pass'))
        passwd_brute_banner = QTableWidgetItem(data.get('banner'))
        time = str(int(data.get('time')))
        # print(time)
        passwd_brute_time = QTableWidgetItem(time)
        self.Ui.tableWidget_passwd_brute_result.setSortingEnabled(False)
        self.Ui.tableWidget_passwd_brute_result.setItem(row, 0, passwd_brute_ip)
        self.Ui.tableWidget_passwd_brute_result.setItem(row, 1, passwd_brute_port)
        self.Ui.tableWidget_passwd_brute_result.setItem(row, 2, passwd_brute_service)
        self.Ui.tableWidget_passwd_brute_result.setItem(row, 3, passwd_brute_user)
        self.Ui.tableWidget_passwd_brute_result.setItem(row, 4, passwd_brute_pass)
        self.Ui.tableWidget_passwd_brute_result.setItem(row, 5, passwd_brute_banner)
        self.Ui.tableWidget_passwd_brute_result.setItem(row, 6, passwd_brute_time)
        # 自动调节列宽度
        # self.Ui.tableWidget_passwd_brute_result.setVisible(False)
        # self.Ui.tableWidget_passwd_brute_result.resizeColumnsToContents()
        # self.Ui.tableWidget_passwd_brute_result.setVisible(True)
        self.Ui.tableWidget_passwd_brute_result.setSortingEnabled(True)

    def passwd_brute_stop(self):
        self.update_data_passwd_brute_log("发出停止信号，请等待...")
        self.Passwd_Brute_obj.portscan_Queue.queue.clear()
        self.Passwd_Brute_obj.pwdscan_Queue.queue.clear()
        self.Passwd_Brute_obj.stop_flag = 1
        self.Ui.pushButton_passwd_brute_start.setEnabled(True)
        self.Ui.pushButton_passwd_brute_stop.setEnabled(False)

    # 得到选中的方法
    def get_methods_passwd_brute(self):
        all_data = []
        item = QtWidgets.QTreeWidgetItemIterator(self.Ui.treeWidget_passwd_brute_service)
        # 该类的value()即为QTreeWidgetItem
        while item.value():
            if not item.value().parent():  # 判断有没有父节点
                pass
            else:  # 输出所有子节点
                if item.value().checkState(0) == QtCore.Qt.Checked:
                    # print(item.value().text(0))
                    all_data.append(item.value().text(0))
            item = item.__iadd__(1)
        # print(all_data)
        # 返回所有选中的数据
        return all_data
    #统一异常处理
    def HandleException(self, excType, excValue, tb):
        currentTime = datetime.datetime.now()  # 时间戳
        self.__Logger.info('Timestamp: %s' % (currentTime.strftime("%Y-%m-%d %H:%M:%S")))
        ErrorMessage = ''.join(traceback.format_exception(excType, excValue, tb))
        self.__Logger.error('ErrorMessage: %s' % ErrorMessage)  # 将异常信息记录到日志中
        self.__Logger.error('sys.excepthook: %s' % sys.excepthook)
        self.__Logger.error('excType: %s' % excType)
        self.__Logger.error('excValue: %s' % str(excValue))
        self.__Logger.error('tb: %s' % tb)
        self.Ui.plainTextEdit_log_log.appendPlainText('ErrorMessage: %s' % ErrorMessage)
        self.Ui.plainTextEdit_log_log.appendPlainText('sys.excepthook: %s' % sys.excepthook)
        self.Ui.plainTextEdit_log_log.appendPlainText('excType: %s' % excType)
        self.Ui.plainTextEdit_log_log.appendPlainText('tb: %s' % tb)
        # box = QtWidgets.QMessageBox()
        # box.warning(self, "错误", ErrorMessage)
        self.Ui.statusBar.showMessage("Error:程序发生错误，请查看程序日志页面！",5000)
        # box.close()

    def fofa_setting(self):
        self.WChild_fofa = Ui_TableWidget()
        self.dialog_fofa = QtWidgets.QDialog(self)
        self.WChild_fofa.setupUi(self.dialog_fofa)
        self.dialog_fofa.setWindowIcon(QtGui.QIcon('Conf/main.png'))
        self.dialog_fofa.setWindowTitle("网络空间KEY设置")
        self.dialog_fofa.show()
        sql_poc = "SELECT * from vuln_collect"
        data = self.sql_search(sql_poc, 'dict')
        self.WChild_fofa.tableWidget_result.setSortingEnabled(False)
        self.WChild_fofa.tableWidget_result.setColumnCount(4)
        self.WChild_fofa.tableWidget_result.setHorizontalHeaderLabels(['id', 'name', 'value', 'type'])
        for i in data:
            row = self.WChild_fofa.tableWidget_result.rowCount()  # 获取行数
            self.WChild_fofa.tableWidget_result.setRowCount(row + 1)
            idItem = QTableWidgetItem(i.get('id'))
            nameItem = QTableWidgetItem(i.get('name'))
            valueItem = QTableWidgetItem(i.get('value'))
            typetem = QTableWidgetItem(i.get('type'))
            self.WChild_fofa.tableWidget_result.setItem(row, 0, idItem)
            self.WChild_fofa.tableWidget_result.setItem(row, 1, nameItem)
            self.WChild_fofa.tableWidget_result.setItem(row, 2, valueItem)
            self.WChild_fofa.tableWidget_result.setItem(row, 3, typetem)

        self.WChild_fofa.tableWidget_result.setVisible(False)
        self.WChild_fofa.tableWidget_result.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.WChild_fofa.tableWidget_result.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)

        # self.WChild_fofa.tableWidget_result.resizeColumnToContents(0)
        # self.WChild_fofa.tableWidget_result.resizeColumnToContents(1)

        # self.WChild_fofa.tableWidget_result.se

        self.WChild_fofa.tableWidget_result.setVisible(True)
        self.WChild_fofa.tableWidget_result.setSortingEnabled(True)
        self.WChild_fofa.pushButton_save.clicked.connect(self.save_fofa_setting)
        # return
    def save_fofa_setting(self):
        conn = sqlite3.connect(DB_NAME)
        # 创建一个游标 curson
        cursor = conn.cursor()
        try:
            sql = 'drop table if exists vuln_collect;'
            cursor.execute(sql)
        except Exception as e:
            self.__Logger.error(str(e))
            box = QtWidgets.QMessageBox()
            box.warning(self, "错误", "数据表删除失败,请查看日志！")
            return 0

        try:
            # 执行一条语句,创建 user表 如不存在创建
            sql = 'CREATE TABLE "vuln_collect" ("id" text NOT NULL,"name" TEXT,"value" TEXT,"type" TEXT,PRIMARY KEY ("id"));'
            # sql = 'create table IF NOT EXISTS vuln_poc ("id" integer PRIMARY KEY AUTOINCREMENT,"cms_name" varchar(30),"vuln_file" varchar(50),"vuln_name" varchar(30),"vuln_author" varchar(50),"vuln_referer" varchar(50),"vuln_description" varchar(200),"vuln_identifier" varchar(100),"vuln_solution" varchar(500),  "ispoc" integer(1),"isexp" integer(1))'
            cursor.execute(sql)
            data=[]
            insert_sql = 'INSERT INTO "vuln_collect" VALUES (?,?, ?,?);'
            for i in range(0, self.WChild_fofa.tableWidget_result.rowCount()):  # 循环行
                for j in range(0, self.WChild_fofa.tableWidget_result.columnCount()):  # 循环列
                    data.append(self.WChild_fofa.tableWidget_result.item(i, j).text())  # 空格分隔
                cursor.execute(insert_sql, (data[0],data[1],data[2],data[3]))
                data = []
            conn.commit()  # 提交
            self.dialog_fofa.close()
            box = QtWidgets.QMessageBox()
            box.warning(self, "Success", "保存成功！")
        except Exception as e:
            self.__Logger.error(str(e))
            box = QtWidgets.QMessageBox()
            box.warning(self, "Success", "保存失败,请查看日志！")
            return 0
    def fofa_go(self):
        fofa_text = self.Ui.fofa_text.text()
        if not fofa_text:
            box = QtWidgets.QMessageBox()
            box.warning(self, "Error", "请输入查询条件")
            return
        fofa_field = self.get_fofa_methods()
        fofa_type = self.Ui.fofa_type.currentText()
        fofa_page = self.Ui.fofa_page.currentText()
        fofa_num = self.Ui.fofa_num.currentText()
        fofa_timeout = self.Ui.fofa_timeout.currentText()
        # self.fofa_tab_addpage(["host","title","ip","domain","port","country","city"],[["1","2","3","4","5","6","7"]],page_title="查询条件")

        self.fofa_obj = Fofa_Start(self,DB_NAME,fofa_field, fofa_type, int(fofa_num), int(fofa_timeout),fofa_text,int(fofa_page))  # 创建一个线程
        self.fofa_obj._data.connect(self.update_data_fofa)  # 线程发过来的信号挂接到槽函数update_sum
        self.fofa_obj._data_error.connect(self.update_data_error_fofa)  # 线程发过来的信号挂接到槽函数update_sum
        self.Ui.fofa_go.setEnabled(False)
        self.fofa_obj.start()  # 线程启动
    def update_data_error_fofa(self,error):
        self.Ui.textEdit_fofa_log.append(str(error))
        QtWidgets.QMessageBox().warning(self, "错误", str(error))
        self.Ui.fofa_go.setEnabled(True)

    def update_data_fofa(self,result):
        self.fofa_tab_addpage(result[0],result[1],result[2])
        self.Ui.fofa_go.setEnabled(True)
        # self.fofa_tab_addpage(["host","title","ip","domain","port","country","city"],[["1","2","3","4","5","6","7"]],page_title="查询条件")
    # 得到选中的方法
    def get_fofa_methods(self):
        checked = dict()
        root = self.Ui.treeWidget_fofa.invisibleRootItem()
        signal_count = root.childCount()
        for i in range(signal_count):
            signal = root.child(i)
            checked_sweeps = list()
            num_children = signal.childCount()
            for n in range(num_children):
                child = signal.child(n)
                if child.checkState(0) == QtCore.Qt.Checked:
                    checked_sweeps.append(child.text(0))
            checked[signal.text(0)] = checked_sweeps
        return checked

    def fofa_tab_addpage(self,result_field,result_data,page_title):
        self.Ui.tab_17 = QtWidgets.QWidget()
        self.Ui.tab_17.setObjectName("tab_1111")
        self.Ui.gridLayout_26 = QtWidgets.QGridLayout(self.Ui.tab_17)
        self.Ui.gridLayout_26.setObjectName("gridLayout_11111")
        self.Ui.tableWidget = QtWidgets.QTableWidget(self.Ui.tab_17)
        self.Ui.tableWidget.setObjectName("tableWidget_1111111")
        self.Ui.tableWidget.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.Ui.tableWidget.customContextMenuRequested.connect(lambda :self.createtableWidget_fofaMenu(self.Ui.tableWidget))  # 将菜单的信号链接到自定义菜单槽函数
        self.Ui.tableWidget.setSortingEnabled(False)
        self.Ui.tableWidget.setColumnCount(len(result_field))
        self.Ui.tableWidget.setHorizontalHeaderLabels(result_field)
        self.Ui.tableWidget.verticalHeader().setVisible(False)

        for singdata in result_data:
            row = self.Ui.tableWidget.rowCount()  # 获取行数
            self.Ui.tableWidget.setRowCount(row + 1)
            i=0
            for data in singdata:
                # print(data)
                Item = QTableWidgetItem(str(data))
                self.Ui.tableWidget.setItem(row, i, Item)
                i=i+1
        # self.Ui.tableWidget_vuln.horizontalHeader().setDefaultSectionSize(self.Ui.tableWidget.width()/len(data_list[0]))
        self.Ui.tableWidget.resizeColumnToContents(0)
        self.Ui.tableWidget.setSortingEnabled(True)
        #列平均分
        # self.Ui.tableWidget.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.Ui.tableWidget.horizontalHeader().setStretchLastSection(True)



        self.Ui.gridLayout_26.addWidget(self.Ui.tableWidget, 0, 0, 1, 1)
        self.Ui.tabWidget_fofa.addTab(self.Ui.tab_17, "")
        self.Ui.tabWidget_fofa.setTabText(self.Ui.tabWidget_fofa.indexOf(self.Ui.tab_17), page_title)
        self.Ui.tabWidget_fofa.setCurrentIndex(self.Ui.tabWidget_fofa.count()-1)
    def fofa_tab_addpage_help(self,help_data):
        self.Ui.tab_17 = QtWidgets.QWidget()
        self.Ui.tab_17.setObjectName("tab_1111")
        self.Ui.gridLayout_26 = QtWidgets.QGridLayout(self.Ui.tab_17)
        self.Ui.gridLayout_26.setObjectName("gridLayout_11111")
        self.Ui.tabWidget_4 = QTabWidget()
        self.Ui.tabWidget_4.setObjectName(u"tabWidget_4")
        for help_single in help_data:
            title = help_single.get("name")
            value =  help_single.get("value")
            file_name = os.getcwd()+value
            if  os.path.exists(file_name):
                file = open(file_name, 'r', encoding='utf-8')
                html_data = file.read()
                file.close()
                self.Ui.tab_18 = QWidget()
                self.Ui.tab_18.setObjectName(u"tab_18")
                self.Ui.gridLayout_27 = QGridLayout(self.Ui.tab_18)
                self.Ui.gridLayout_27.setObjectName(u"gridLayout_27")
                self.Ui.textEdit = QTextEdit(self.Ui.tab_18)
                self.Ui.textEdit.setObjectName(u"textEdit")
                self.Ui.textEdit.setHtml(html_data)
                self.Ui.gridLayout_27.addWidget(self.Ui.textEdit, 0, 0, 1, 1)
                self.Ui.tabWidget_4.addTab(self.Ui.tab_18, "")
                self.Ui.tabWidget_4.setTabText(self.Ui.tabWidget_4.indexOf(self.Ui.tab_18), title)
        self.Ui.gridLayout_26.addWidget(self.Ui.tabWidget_4, 0, 0, 1, 1)
        self.Ui.tabWidget_fofa.addTab(self.Ui.tab_17, "")
        self.Ui.tabWidget_fofa.setTabText(self.Ui.tabWidget_fofa.indexOf(self.Ui.tab_17), '首页')
        self.Ui.tabWidget_fofa.setCurrentIndex(self.Ui.tabWidget_fofa.count()-1)

    def fofa_open_url(self,obj):
        url  = obj.selectedItems()[0].text()
        if "http://" not in url and "https://" not in url:
            url ="http://"+url
        webbrowser.open(url)
    def fofa_get_icon(self):
        fofa_type = self.Ui.fofa_type.currentText()  # 获取文本
        try:
            icon_hash=''
            url = self.Ui.fofa_text.text()
            if url and 'http' in url:
                response = requests.get(url, timeout=3)
                if response.status_code==200 and response.content:
                    icon_hash =  mmh3.hash(codecs.lookup('base64').encode(response.content)[0])
                else:
                    box = QtWidgets.QMessageBox()
                    box.warning(self, "错误", "远程获取hash失败,请使用本地获取！")

            else:
                filename = self.file_open(r"Text Files (*.ico);;All files(*.*)")
                if filename:
                    try:
                        filesize = os.path.getsize(filename)
                        if filesize > 256000:
                            box = QtWidgets.QMessageBox()
                            box.warning(self, "错误", "文件太大")
                            return
                        f = open(filename, 'rb')
                        data = f.read()
                        f.close()
                        icon_hash = mmh3.hash(codecs.lookup('base64').encode(data)[0])
                    except:
                        box = QtWidgets.QMessageBox()
                        box.warning(self, "错误", "icon-hash获取失败")
                        return
            if icon_hash:
                if "fofa" in fofa_type.lower():
                    self.Ui.fofa_text.setText('icon_hash="%s"' % icon_hash)
                elif "shodan" in fofa_type.lower():
                    self.Ui.fofa_text.setText('http.favicon.hash:%s' % icon_hash)
                else:
                    self.Ui.fofa_text.setText('iconhash:"%s"' % icon_hash)

        except:
            pass
    def createtableWidget_fofaMenu(self,obj):
        obj.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        obj.customContextMenuRequested.connect(self.showContextMenu)
        # 创建QMenu
        self.contextMenu = QtWidgets.QMenu(self)
        self.open = self.contextMenu.addAction(u'打开')
        self.daochu = self.contextMenu.addAction(u'导出')
        self.delete_textEdit = self.contextMenu.addAction(u'删除')
        self.clear_textEdit = self.contextMenu.addAction(u'清空')
        # 将动作与处理函数相关联
        # 这里为了简单，将所有action与同一个处理函数相关联，
        # 当然也可以将他们分别与不同函数关联，实现不同的功能
        self.open.triggered.connect(lambda :self.fofa_open_url(obj))
        self.daochu.triggered.connect(lambda: self.export_file(obj, ''))
        self.clear_textEdit.triggered.connect(lambda: self.Clear_tableWidget(obj))
        self.delete_textEdit.triggered.connect(lambda: self.Delete_tableWidget(obj))
    def closeTab(self,currentIndex):
        # print(currentIndex)
        self.Ui.tabWidget_fofa.removeTab(currentIndex)





if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    # 创建启动界面，支持png透明图片
    splash = QtWidgets.QSplashScreen(QtGui.QPixmap('./Conf/main.png'))
    splash.show()
    splash.showMessage('正在加载……')
    app.processEvents()  # 防止进程卡死
    # 可以显示启动信息
    # # 关闭启动画面
    # splash.close()
    window = MainWindows()
    translator = QTranslator()
    translator.load('./conf/qm/qt_zh_CN.qm') #改变中文菜单
    app.installTranslator(translator)
    translator_2 = QTranslator()
    translator_2.load('./conf/qm/widgets_zh_cn.qm') #改变QTextEdit右键为中文
    app.installTranslator(translator_2)
    window.show()
    splash.finish(window)  # 关闭启动界面
    splash.close()
    sys.exit(app.exec_())
