import base64
import json
import sqlite3
import eventlet
import requests
#DB_NAME 数据库名 
#fofa_text 查询条件
#fofa_type 查询类型
#all_fofa_field  查询显示的字段
#fofa_timeout  超时
#headers headers头
#fofa_num 查询条数
#fofa_page 查询页数
def run(DB_NAME,fofa_text,fofa_type,all_fofa_field,fofa_timeout,headers,fofa_num,fofa_page):
    # 返回数据解释
    # {"Error_Info":"","FoFa_Field":["host","ip"],"FoFa_Data":["baidu.com","127.0.0.1"]}
    # Error_Info：错误信息
    # FoFa_Field 返回的表格头  数据为列表 长度为1
    # FoFa_Data  返回的表格数据  数据为列表
    fofa_api=''
    fofa_email=''
    fofa_key=''
    sql = 'select * from vuln_collect where name = "Fofa_Api" or name = "Fofa_Email" or name = "Fofa_Key"'
    fofa_email_key_Data = sql_search(DB_NAME,sql, 'dict')
    if fofa_email_key_Data:
        for single_data in fofa_email_key_Data:
            if single_data.get("name")=='Fofa_Api':
                fofa_api = single_data.get("value").strip()
            elif single_data.get("name")=='Fofa_Email':
                fofa_email = single_data.get("value").strip()
            elif single_data.get("name")=='Fofa_Key':
                fofa_key = single_data.get("value").strip()
    else:
        return {"Error_Info": "fofa api email key设置错误"}
        # self._data_error.emit("fofa api email key设置错误")
    if fofa_api and fofa_email and fofa_key:
        text = fofa_text.encode(encoding="utf-8")
        text = base64.b64encode(text).decode()
        fofa_field = ','.join(all_fofa_field[fofa_type])
        eventlet.monkey_patch(time=True)
        with eventlet.Timeout(int(fofa_timeout) + 3, False):
            url = fofa_api.replace('${FOFA_EMAIL}', fofa_email).replace('${FOFA_KEY}',fofa_key).replace('${FOFA_NUM}', str(fofa_num)).replace('${FOFA_BASE64}', text).replace('${FOFA_FIELD}', fofa_field)
            # print(url)
            try:
                req = requests.get(url, headers=headers, timeout=int(fofa_timeout), verify=False)
            except Exception as e:
                # self._data_error.emit( str(e))
                return {"Error_Info": str(e)}
            req = req.text
            try:
                req = json.loads(req)['results']
                return {"Error_Info":"","FoFa_Field":all_fofa_field[fofa_type],"FoFa_Data":req}
                # self._data.emit([self.fofa_field['Fofa'], req, self.fofa_text])
                # self.Ui.textEdit_log.append(self.getTime() + "共获取到%s条数据" % len(req))
            except Exception as e:
                # print(e)
                error2 = json.loads(req)['errmsg']
                return {"Error_Info": str(error2)}
        return {"Error_Info": "获取数据超时！"}
    else:
        return {"Error_Info": "fofa api email key设置错误"}


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