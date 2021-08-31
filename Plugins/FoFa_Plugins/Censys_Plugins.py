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
        all_result=[]
        for page in range(int(fofa_page)):
            try:
                sql = "select * from vuln_collect where name='Censys_Secret' or name='Censys_Apiid'"
                sql_result = sql_search(DB_NAME,sql,'dict')
                if len(sql_result)==2:
                    for i in sql_result:
                        if i.get("name") =="Censys_Secret":
                            censys_Secret= i.get("value")

                        elif i.get("name") =="Censys_Apiid":
                            censys_API_ID= i.get("value")
                else:
                    return {"Error_Info": "未查询到用户名或密码！"}
                page=page+1
                MainWindows.Ui.textEdit_fofa_log.append('开始查询第%s页...' % page)
                API_URL = "https://www.censys.io/api/v1/search/ipv4"
                data = {
                    "query": fofa_text,
                    "page": page,
                    "fields": all_fofa_field[fofa_type]
                }
                # print( all_fofa_field[fofa_type])
                res = requests.post(API_URL, data=json.dumps(data), auth=(censys_API_ID, censys_Secret),timeout=fofa_timeout)
                results = res.json()
                data = ''
                MainWindows.Ui.textEdit_fofa_log.append("共获取到%s条数据" % len(results["results"]))

                for single_result in results["results"]:
                    single_data =[]
                    for x in all_fofa_field[fofa_type]:
                        single_data.append(single_result.get(x))
                    all_result.append(single_data)

                # for single_result in results["results"]:
                #     all_result.append(list(single_result.values()))
                    # data+= result["ip"] + "\n"
                if len(results["results"])<100:
                    break
            except Exception as e:
                MainWindows.Ui.textEdit_fofa_log.append(str(str(e)+'----'+str(e.__traceback__.tb_lineno)+'行'))
                break
        return {"Error_Info":"","FoFa_Field":all_fofa_field[fofa_type],"FoFa_Data":all_result}
    except Exception as e:
        return {"Error_Info": str(str(e)+'----'+str(e.__traceback__.tb_lineno)+'行')}
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
