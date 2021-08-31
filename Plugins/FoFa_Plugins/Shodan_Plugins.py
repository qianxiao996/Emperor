import sqlite3
import shodan  
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
        all_result=[]
        sql = 'select * from vuln_collect where name = "Shodan_Key"'
        shodan_key_Data = sql_search(DB_NAME,sql, 'dict')
        if shodan_key_Data:
            api = shodan.Shodan(shodan_key_Data[0]['value'])
            # api=shodan.Shodan("cB9sXwb7l95ZhSJaNgcaO7NQpkzfhQVM") 
            # search=api.search('apache')   
            try:
                search = api.search(fofa_text, int(fofa_page))
            except Exception as e:
                return {"Error_Info": str(str(e)+'----'+str(e.__traceback__.tb_lineno)+'行')}

            for result in search['matches']:
                # print(result)
                single_result = []
                for field in fofa_field:
                    if field=='url':
                        url = 'http://'+ result['ip_str'].strip()+":"+str(result['port'])
                        single_result.append(url)
                    else:
                        sing_data = result.get(field)
                        if not sing_data:
                            sing_data =  result.get('location').get(field)
                        single_result.append(sing_data)
                all_result.append(single_result)

            if len(all_result)==0:
                return {"Error_Info": "未查询到数据"}
            else:
                return {"Error_Info":"","FoFa_Field":all_fofa_field[fofa_type],"FoFa_Data":all_result}

        else:
            return {"Error_Info": "key设置错误"}
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
    all_fofa_field = {'Censys': ['host', 'ip'], 'Fofa': ['host', 'title', 'ip', 'domain', 'port', 'country', 'city'], 'Shodan': ['ip_str', 'port', 'city', 'country_name', 'vulns'], 'ZoomEye': ['ip']}
    a=run('',"D:\code\Python37\obj\Emperor\Conf\DB.db","discuz",all_fofa_field,5,{},1000,1)
    print(a)
