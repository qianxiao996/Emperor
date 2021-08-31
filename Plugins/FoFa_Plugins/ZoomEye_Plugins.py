import sqlite3
import json,requests
#DB_NAME 数据库名 
#fofa_text 查询条件
#fofa_type 查询类型
#all_fofa_field  查询显示的字段
#fofa_timeout  超时
#headers headers头
#fofa_num 查询条数
#fofa_page 查询页数
def run(MainWindows,DB_NAME,fofa_text,fofa_type,all_fofa_field,fofa_timeout,headers,fofa_num,fofa_page):
    # 返回数据解释
    # {"Error_Info":"","FoFa_Field":["host","ip"],"FoFa_Data":["baidu.com","127.0.0.1"]}
    # Error_Info：错误信息
    # FoFa_Field 返回的表格头  数据为列表 长度为1
    # FoFa_Data  返回的表格数据  数据为列表
    try:
        fofa_field = all_fofa_field.get(fofa_type)
        if not MainWindows.zoomeye_access_token:
            zoomeye_password=''
            zoomeye_username=''
            MainWindows.Ui.textEdit_fofa_log.append('正在登陆...')
            sql = "select * from vuln_collect where name='Zoomeye_Username' or name='Zoomeye_Password'"
            sql_result = sql_search(DB_NAME,sql,'dict')
            if len(sql_result)==2:
                for i in sql_result:
                    if i.get("name") =="Zoomeye_Username":
                        zoomeye_username= i.get("value")

                    elif i.get("name") =="Zoomeye_Password":
                        zoomeye_password= i.get("value")
            else:
                return {"Error_Info": "未查询到用户名或密码！"}
            if zoomeye_password and zoomeye_username:
                result = ZoomEye_login(MainWindows,zoomeye_username,zoomeye_password)
                if result:
                    MainWindows.zoomeye_access_token=result
                    MainWindows.Ui.textEdit_fofa_log.append('登陆成功！')
                    all_result = ZoonmEye_search(MainWindows,fofa_text,int(fofa_page),int(fofa_timeout),fofa_field)
                else:
                    return {"Error_Info": "登陆失败！"}
            else:
                return {"Error_Info": "未查询到用户名或密码！"}
                
        else:
            all_result = ZoonmEye_search(MainWindows,fofa_text,int(fofa_page),int(fofa_timeout),fofa_field)
        if len(all_result)==0:
                return {"Error_Info": "未查询到数据"}
        else:
            MainWindows.Ui.textEdit_fofa_log.append('查询结束！')
            return {"Error_Info":"","FoFa_Field":all_fofa_field[fofa_type],"FoFa_Data":all_result}

    except Exception as e:
        return {"Error_Info": str(str(e)+'----'+str(e.__traceback__.tb_lineno)+'行')}


def ZoomEye_login(MainWindows,zoomeye_username,zoomeye_password):
    data = {
        'username': zoomeye_username,
        'password': zoomeye_password
    }
    data_encoded = json.dumps(data)  # dumps 将 python 对象转换成 json 字符串
    try:
        r = requests.post(url='https://api.zoomeye.org/user/login', data=data_encoded,timeout=5)
        r_decoded = json.loads(r.text)  # loads() 将 json 字符串转换成 python 对象
        # print(r_decoded)
        zoomeye_access_token = r_decoded['access_token']
        return zoomeye_access_token
    except Exception as e:
        # print(str(e))
        MainWindows.Ui.textEdit_fofa_log.append(str(e))
        return False
def ZoonmEye_search(MainWindows,text,all_page,timeout,fofa_field):

    headers2 = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36',
        'Authorization': 'JWT ' + MainWindows.zoomeye_access_token,
    }
    for page in range(all_page):
        data = ''
        page = page + 1
        MainWindows.Ui.textEdit_fofa_log.append('开始查询第%s页...' % page)
        # try:
        url = 'https://api.zoomeye.org/host/search?query={}&facet=app,os&page='.format(text)
        r = requests.get(url=url + str(page), headers=headers2,timeout=timeout)
        # print(r.text)
        r_decoded = json.loads(r.text)
        try:
            MainWindows.Ui.textEdit_fofa_log.append("共获取到%s条数据" % len(r_decoded['matches']))
            all_result=[]
            for x in r_decoded['matches']:
                single_result = []
                for field in fofa_field:
                    if field=='url':
                        url = 'http://'+ x.get('ip').strip()+":"+str(x.get('portinfo').get('port'))
                        single_result.append(url)
                    elif field=='port':
                        single_result.append(x.get('portinfo').get('port'))
                    elif field=='title':
                        try:
                            single_result.append(x.get('portinfo').get('title')[0])
                        except:
                            single_result.append(str(x.get('portinfo').get('title')))
                    elif field=='continent':
                        single_result.append(x.get('geoinfo').get('continent').get('names').get('zh-CN'))
                    elif field=='country':
                        single_result.append(x.get('geoinfo').get('country').get('names').get('zh-CN'))
                    elif field=='city':
                        single_result.append(x.get('geoinfo').get('city').get('names').get('zh-CN'))
                    else:
                        single_result.append(x.get(field))
                all_result.append(single_result)
                # data += 'http://' + x['ip']+":"+str(x['portinfo']['port'])+'\n'
                # print(x['portinfo']['port'])
            if len(r_decoded) < 20:
                break
        except Exception as e:
            # print(str(e)+'----'+str(e.__traceback__.tb_lineno)+'行')
            try:

                MainWindows.Ui.textEdit_fofa_log.append(str(r_decoded['message']))
            except:
                MainWindows.Ui.textEdit_fofa_log.append(str(e)+'----'+str(e.__traceback__.tb_lineno)+'行')
                
    return all_result
def sql_search(DB_NAME,sql, type='list'):
    if type == 'dict':
        conn = sqlite3.connect(DB_NAME)
        conn.row_factory = dict_factory
    else:
        conn = sqlite3.connect(DB_NAME)
    # 创建一个游标 curson
    cursor = conn.cursor()
    # 列出所有数据
    cursor.execute(sql)
    values = cursor.fetchall()
    return values

def dict_factory(cursor, row):
    d = {}
    for idx, col in enumerate(cursor.description):
        d[col[0]] = row[idx]
    return d

if __name__=="__main__":
    pass
    # all_fofa_field = {'Censys': ['host', 'ip'], 'Fofa': ['host', 'title', 'ip', 'domain', 'port', 'country', 'city'], 'Shodan': ['ip_str', 'port', 'city', 'country_name', 'vulns'], 'ZoomEye': ['ip']}
    # a=run("D:\code\Python37\obj\Emperor\Conf\DB.db","discuz",all_fofa_field,5,{},1000,1)
    # print(a)
