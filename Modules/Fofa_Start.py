import base64
import json
import os

import eventlet
import importlib
from urllib.parse import urlparse

import requests
from PyQt5 import QtWidgets
from PyQt5.QtCore import QThread, pyqtSignal


class Fofa_Start(QThread):
    """该线程用于计算耗时的累加操作"""
    _data = pyqtSignal(list)  # 信号类型 str
    _data_error =pyqtSignal(str)  # 信号类型 str
    def __init__(self,MainWindows,DB_NAME,fofa_field, fofa_type, fofa_num, fofa_timeout,fofa_text,fofa_page,parent=None):
        super(Fofa_Start,self).__init__(parent)
        self.MainWindows = MainWindows
        self.DB_NAME=DB_NAME
        self.fofa_field = fofa_field
        self.fofa_type = fofa_type
        self.fofa_num = fofa_num
        self.fofa_timeout =fofa_timeout
        self.fofa_text= fofa_text
        self.fofa_page = fofa_page
        self.headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36'}


    def run(self):

        try:
            sql = 'select * from vuln_collect where name = \''+self.fofa_type+'_Plugins\' and type=\'plugins\''
            fofa_plugins =self.MainWindows.sql_search(sql, 'dict')
            if fofa_plugins:
                fofa_plugins = os.getcwd()+'/'+fofa_plugins[0]['value']
                nnnnnnnnnnnn1 = importlib.machinery.SourceFileLoader(fofa_plugins[:-3], fofa_plugins).load_module()
                result = nnnnnnnnnnnn1.run(self.MainWindows,self.DB_NAME,self.fofa_text, self.fofa_type ,self.fofa_field, self.fofa_timeout, self.headers, self.fofa_num,self.fofa_page)
                if result.get("Error_Info"):
                    self._data_error.emit(result.get("Error_Info"))
                else:
                    self._data.emit([result.get("FoFa_Field"), result.get("FoFa_Data"), self.fofa_type +":"+self.fofa_text])
            else:
                self._data_error.emit(str('未获取到插件路径'))
        except Exception as e:
            self._data_error.emit(str(e))