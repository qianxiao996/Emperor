# -*- coding: UTF-8 -*-
#!/usr/bin/python
import requests
def domain_info():
    info={
        'plugins_name': '脚本名称',  #漏洞名称
        'plugins_author':'qianxiao996',  #插件作者
        'plugins_description':'''插件描述''', #插件描述
        'plugins_key1':'''key1''', #插件key
        'plugins_key2':'key2',#插件key
        'plugins_key3':'key3'#插件key
    }
    return info
# obj: obj对象  domain：域名  key1：key1  key2：key2  key3：key3 heads：http自定义头信息 timeout：超时设置
def do_start(obj,domain,key1,key2,key3,heads,timeout):
    try:
    # 返回参数
    #Result返回是否存在，
    #domain 主域名
    #subdomain 子域名
    #subdomain_ip 子域名ip（可为空）
    #subdomain_title 子域名标题（可为空）
    #Result_Info为返回的信息，可以为Paylaod 
    #Debug debug信息 默认不会显示，勾选显示调试信息会输出此结果
    #Error_Info无论何时都会输出
    #最后要返回个END 不然会爆出异常结束。
        result = {"Result":True,"domain":domain,"subdomain":"qianxiao996.cn","subdomain_ip":"","subdomain_title":"","Debug_Info":"","Error_Info":""}
        obj.result_echo(result)
    except Exception as e:
        result['Error_Info'] = str(e)+str(e.__traceback__.tb_lineno)+'行'
    return "END"
