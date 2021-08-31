import base64
import binascii
import collections
import html
import random
import re
import string
import urllib.parse

from Gui.Binary import Ui_Binary
from Gui.KEY_1 import Ui_KEY1
from Gui.KEY_2 import Ui_KEY2
from PyQt5 import QtWidgets
from PyQt5.QtWidgets import *


class Encode_Encrypt:
    def __init__(self,Mainwindows,type, encode_type, text):
        super().__init__()
        self.Mainwindows =Mainwindows
        self.type=type
        self.encode_type = encode_type
        self.text=text
    def start(self):
        if self.type=="encode":
             self.encode(self.encode_type,self.text)
        elif self.type=="decode":
             self.decode(self.encode_type,self.text)
        elif self.type=="encrypt":
             self.encrypt(self.encode_type,self.text)
        elif self.type=="decrypt":
             self.decrypt(self.encode_type,self.text)
        elif self.type=="binary":
            self.Binary(self.encode_type,self.text)
        return

    # 编码
    def encode(self, encode_type,text):
        try:
            result_text = ''
            if encode_type == '图片-Base64':
                try:
                    filename = self.file_open(r"Image Files (*.jpg);;All files(*.*)")
                    if filename:
                        with open(filename, 'rb') as f:
                            base64_data = base64.b64encode(f.read())
                            s = base64_data.decode()
                            result_text= str('data:image/%s;base64,%s' % (filename[-3:], s))
                    else:
                        pass
                except Exception as  e:
                    print(e)
                    result_text=('转换失败！')
            elif encode_type == '图片-Hex':
                try:
                    filename = self.file_open(r"Image Files (*.jpg);;All files(*.*)")
                    if filename:
                        with open(filename, 'rb') as f:
                            hex_data = f.read()
                            hexstr = binascii.hexlify(hex_data).decode("utf-8")
                            hexstr = hexstr.upper()
                        result_text= (str('%s' % (hexstr)))
                    else:
                        pass
                except:
                    result_text=('转换失败！')

            # print(encode_type)
            elif text == '':
                result_text= '请输入一个源字符串！'
            # print(encode_type)
            elif encode_type == 'URL-UTF8':
                text = text.encode('utf-8')
                result_text = urllib.parse.quote(text)
            elif encode_type == 'URL-GB2312':
                text = text.encode('gb2312')
                result_text = urllib.parse.quote(text)
            elif encode_type == 'Unicode':
                text = text.encode('unicode_escape')
                result_text = str(text, encoding='utf-8')
            elif encode_type == 'Escape(%U)':
                text = text.encode('unicode_escape')
                result_text = str(text, encoding='utf-8').replace('\\u', '%u')
            elif encode_type == 'HtmlEncode':
                result_text = html.escape(text)
            elif encode_type == 'ASCII':
                result = ''
                for i in text:
                    result = str(result) + str(ord(str(i))) + ' '
                result_text = str(result)[:-1]
            elif encode_type == 'Base16':
                text = text.lower()
                text = base64.b16encode(text.encode("utf-8"))
                result_text = str(text, encoding='utf-8')
            elif encode_type == 'Base32':
                text = base64.b32encode(text.encode("utf-8"))
                result_text = str(text, encoding='utf-8')
            elif encode_type == 'Base64':
                text = base64.b64encode(text.encode("utf-8"))
                result_text = str(text, encoding='utf-8')
            elif encode_type == 'Str-Hex':
                result = ''
                for i in text:
                    single = str(hex(ord(str(i))))
                    result = result + single
                result_text = (str(result)).replace('0x', '')
            elif encode_type == 'Shellcode':
                result = ''
                for i in text:
                    single = str(hex(ord(str(i))))
                    result = result + single
                result_text = (str(result)).replace('0x', '\\x')
            elif encode_type == 'Qwerty':
                str1 = "qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM"
                str2 = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
                result_text = ""
                for s in text:
                    if s in str1:
                        if s != ' ':
                            result_text = result_text + str1[str2.index(s)]
                        else:
                            result_text = result_text + ' '
                    else:
                        result_text = 'Qwerty只能对字母加密!'
            if result_text != "":
                self.Mainwindows.Ui.encode_Result_text.setText(str(result_text))
            else:
                self.Mainwindows.Ui.encode_Result_text.setText("编码失败！")
        except Exception as e:
            self.Mainwindows.Ui.encode_Result_text.setText(str(e))
            # print(str(e))

    # 解码
    def decode(self, decode_type,text):
        try:
            result_text = ''
            text =text.strip()
            # print(decode_type)
            if text == '':
                result_text= ('请输入一个源字符串！')

            elif decode_type == 'URL-UTF8':
                result_text = str(urllib.parse.unquote(text))
            elif decode_type == 'URL-GB2312':
                result_text = str(urllib.parse.unquote(text, 'gb2312'))
            elif decode_type == 'Unicode':
                result_text = bytes(text, encoding="utf8").decode('unicode_escape')
            elif decode_type == 'Escape(%U)':
                text = text.replace('%u', '\\u').replace('%U', '\\u')
                result_text = bytes(text, encoding="utf8").decode('unicode_escape')
            elif decode_type == 'HtmlEncode':
                result_text = html.unescape(text)
            elif decode_type == 'ASCII':
                if ':' in text:
                    text = text.split(":")
                elif ' ' in text:
                    text = text.split(" ")
                elif ';' in text:
                    text = text.split(";")
                elif ',' in text:
                    text = text.split(",")
                else:
                    list22 = []
                    list22.append(text)
                    text = list22
                # print(text)
                result = ''
                for i in text:
                    if i != '':
                        # print(i)
                        # print(chr(int(i)))
                        result = result + chr(int(i))
                result_text = result
            elif decode_type == 'Base16':
                text = text.upper()
                text = base64.b16decode(text.encode("utf-8"))
                result_text = str(text, encoding='utf-8')
            elif decode_type == 'Base32':
                text = base64.b32decode(text.encode("utf-8"))
                result_text = str(text, encoding='utf-8')
            elif decode_type == 'Base64':
                text = base64.b64decode(text.encode("utf-8"))
                result_text = str(text, encoding='utf-8')
            elif decode_type == 'Str-Hex':
                text = text.replace('0x', '').replace('0X', '')
                result_text = str(bytes.fromhex(text), encoding="utf-8")
            elif decode_type == 'Shellcode':
                text = text.lower()
                result = ''
                if "0x" in text and "\\x" not in text:
                    text = text.split('0x')
                elif  "\\x" in text and "0x" not in text:
                    text = text.split('\\x')
                else:
                    result_text="请输入正确的格式，如：\n\\x61\\x00\\x62\\x00\\x63\n0x610x000x620x000x63"
                    self.Mainwindows.Ui.encode_Result_text.setText(str(result_text))
                    return
                for i in text:
                    single = str(bytes.fromhex(i.rjust(2,'0')), encoding="utf-8")
                    result = result + single
                result_text = str(result)
            elif decode_type == 'Qwerty':
                letter = {
                    'q': 'a', 'w': 'b', 'e': 'c', 'r': 'd', 't': 'e', 'y': 'f', 'u': 'g',
                    'i': 'h', 'o': 'i', 'p': 'j', 'a': 'k', 's': 'l', 'd': 'm', 'f': 'n',
                    'g': 'o', 'h': 'p', 'j': 'q', 'k': 'r', 'l': 's', 'z': 't',
                    'x': 'u', 'c': 'v', 'v': 'w', 'b': 'x', 'n': 'y', 'm': 'z',

                    'Q': 'A', 'W': 'B', 'E': 'C', 'R': 'D', 'T': 'E', 'Y': 'F', 'U': 'G',
                    'I': 'H', 'O': 'I', 'P': 'J', 'A': 'K', 'S': 'L', 'D': 'M', 'F': 'N',
                    'G': 'O', 'H': 'P', 'J': 'Q', 'K': 'R', 'L': 'S', 'Z': 'T',
                    'X': 'U', 'C': 'V', 'V': 'W', 'B': 'X', 'N': 'Y', 'M': 'Z',
                }
                result_text = ''
                for i in range(0, len(text)):
                    if text[i] != ' ':
                        if letter.get(text[i]):
                            result_text = result_text + letter.get(text[i])
                        else:
                            result_text+=text[i]
                    else:
                        result_text = result_text + ' '
            elif decode_type == '图片-Base64':
                try:
                    file_name = self.file_save('tupian.jpg',r"Image Files (*.jpg);;All files(*.*)")
                    # print(file_name)
                    str2 = base64.b64decode(
                        text.replace('data:image/jpg;base64,', '').replace('data:image/jpeg;base64,', '').replace(
                            'data:image/png;base64,', '').replace('data:image/gif;base64,', ''))
                    file1 = open(file_name, 'wb')
                    file1.write(str2)
                    file1.close()
                    QMessageBox.information(None, 'Success', '转换成功，文件位置:%s' % file_name)
                    result_text = '转换成功，文件位置:\n%s' % file_name
                except Exception as e:
                    print(e)
                    result_text = "转换失败！"
                    pass
            elif decode_type == '图片-Hex':
                try:
                    file_name = self.file_save('hextupian.jpg',r"Image Files (*.jpg);;All files(*.*)")
                    # print(file_name)
                    file1 = open(file_name, 'wb')
                    pic = binascii.a2b_hex(text.encode())
                    file1.write(pic)
                    file1.close()
                    QMessageBox.information(None, 'Success', '转换成功，文件位置:%s' % file_name)
                    result_text = '转换成功，文件位置:\n%s' % file_name
                except:
                    result_text = "转换失败！"
                    pass
            if result_text != "":
                self.Mainwindows.Ui.encode_Result_text.setText(str(result_text))
            else:
                self.Mainwindows.Ui.encode_Result_text.setText ('解码失败!')
        except Exception as e:
            self.Mainwindows.Ui.encode_Result_text.setText (str(e))
            # print(e)
            pass

    # encrypt
    def encrypt(self, encrypt_type,text):
        try:
            result_text = ''
            # print(encrypt_type)
            if text == '':
                result_text =('请输入一个源字符串！')
            elif encrypt_type == 'Rot13':
                d = {chr(i + c): chr((i + 13) % 26 + c) for i in range(26) for c in (65, 97)}
                result_text = ''.join([d.get(c, c) for c in text])
            elif encrypt_type == '凯撒密码':
                t = ""
                for c in text:
                    if 'a' <= c <= 'z':  # str是可以直接比较的
                        t += chr(ord('a') + ((ord(c) - ord('a')) + 3) % 26)
                    elif 'A' <= c <= 'Z':
                        t += chr(ord('A') + ((ord(c) - ord('A')) + 3) % 26)
                    else:
                        t += c
                result_text = t
            elif encrypt_type == '栅栏密码':
                self.WChild_zhalan = Ui_KEY1()
                self.dialog = QtWidgets.QDialog()
                self.WChild_zhalan.setupUi(self.dialog)
                self.dialog.show()
                self.WChild_zhalan.keyenter.clicked.connect(lambda :self.zhalanEncrypto(text))
                return
            elif encrypt_type == '培根密码':
                CODE_TABLE = {  # 培根字典
                    'aaaaa': 'a', 'aaaab': 'b', 'aaaba': 'c', 'aaabb': 'd', 'aabaa': 'e', 'aabab': 'f', 'aabba': 'g',
                    'aabbb': 'h', 'abaaa': 'i', 'abaab': 'j', 'ababa': 'k', 'ababb': 'l', 'abbaa': 'm', 'abbab': 'n',
                    'abbba': 'o', 'abbbb': 'p', 'baaaa': 'q', 'baaab': 'r', 'baaba': 's', 'baabb': 't', 'babaa': 'u',
                    'babab': 'v', 'babba': 'w', 'babbb': 'x', 'bbaaa': 'y', 'bbaab': 'z'
                }
                str = text.lower()
                listStr = ''
                for i in str:
                    if i in CODE_TABLE.values():
                        # 将键、值各化为一个列表，取出i在value的位置后根据下标找到对应的键
                        listStr += list(CODE_TABLE.keys())[list(CODE_TABLE.values()).index(i)]
                result_text = listStr.upper()  # 大写输出
            elif encrypt_type == '摩斯密码':
                CODE = {'A': '.-', 'B': '-...', 'C': '-.-.',
                        'D': '-..', 'E': '.', 'F': '..-.',
                        'G': '--.', 'H': '....', 'I': '..',
                        'J': '.---', 'K': '-.-', 'L': '.-..',
                        'M': '--', 'N': '-.', 'O': '---',
                        'P': '.--.', 'Q': '--.-', 'R': '.-.',
                        'S': '...', 'T': '-', 'U': '..-',
                        'V': '...-', 'W': '.--', 'X': '-..-',
                        'Y': '-.--', 'Z': '--..',
                        '0': '-----', '1': '.----', '2': '..---',
                        '3': '...--', '4': '....-', '5': '.....',
                        '6': '-....', '7': '--...', '8': '---..',
                        '9': '----.', '?': '..--..', '/': '-..-.',
                        '()': '-.--.-', '-': '-....-', '.': '.-.-.-'
                        }
                msg = ''
                text=text.upper()
                for char in text:
                    if char in CODE:
                        if char == ' ':
                            pass
                        else:
                            msg += (CODE[char.upper()] + ' ')
                    else:
                        msg = '文本中含有不能识别的字符！'
                result_text = msg
            elif encrypt_type == '云影密码':
                charList = [chr(i) for i in range(ord('A'), ord('Z') + 1)]
                cipher = [i for i in text.upper()]
                tmp = []
                ret = []
                for i in range(len(cipher)):
                    for j in range(len(charList)):
                        if charList[j] == cipher[i]:
                            tmp.append(j + 1)
                for i in tmp:
                    res = ''
                    if i >= 8:
                        for j in range(0, int(i / 8)):
                            res += '8'
                    if i % 8 >= 4:
                        for j in range(0, int(i % 8 / 4)):
                            res += '4'
                    if i % 4 >= 2:
                        for j in range(0, int(i % 4 / 2)):
                            res += '2'
                    if i % 2 >= 1:
                        for j in range(0, int(i % 2 / 1)):
                            res += '1'
                    ret.append(res + '0')
                result_text = ''.join(ret)[:-1]
                # print(result_text)
            elif encrypt_type == '四方密码':
                self.WChild = Ui_KEY2()
                self.dialog = QtWidgets.QDialog()
                self.WChild.setupUi(self.dialog)
                self.dialog.show()
                self.WChild.enter.clicked.connect(lambda :self.sifang_encrypt(text))
                return 0
            elif encrypt_type == '当铺密码':
                mapping_data = [['田'], ['由'], ['中'], ['人'], ['工'], ['大'], ['王'], ['夫'], ['井'], ['羊']]
                try:
                    result = []
                    for c in text:
                        c_list = mapping_data[int(c)]
                        c_index = random.randint(0, len(c_list) - 1)
                        result.append(c_list[c_index])
                    result_text = ''.join(result)
                except:
                    result_text = '未找到该字符串对应的中文！'
            elif encrypt_type == '仿射密码':
                self.WChild = Ui_KEY2()
                self.dialog = QtWidgets.QDialog()
                self.WChild.setupUi(self.dialog)
                self.dialog.show()
                self.WChild.enter.clicked.connect(lambda :self.fangshe_encrypt(text))
                return
            elif encrypt_type=="移位密码":
                inputStr = text
                #
                result = ''
                for j in range(26):
                    result_list = []
                    for i, num in zip(inputStr, range(len(inputStr))):
                        # print(i)
                        if i.islower:
                            caseS1 = string.ascii_lowercase * 2
                        if i in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
                            caseS1 = string.ascii_uppercase * 2
                        status = caseS1.find(i)
                        if status != -1:
                            result_list.append(caseS1[status + j])
                        else:
                            result_list.append(inputStr[num])
                    text2 = ("".join(result_list), "向右偏移了{}位".format(j))
                    result += text2[0] + ' ' + text2[1] + '\n'
                result_text = result
            elif encrypt_type == '维吉尼亚密码':
                self.WChild = Ui_KEY1()
                self.dialog = QtWidgets.QDialog()
                self.WChild.setupUi(self.dialog)
                self.dialog.show()
                self.WChild.keyenter.clicked.connect(lambda:self.VigenereEncrypto(text.lower()))
                return 0
            elif encrypt_type == '埃特巴什码':
                str1 = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
                str2 = "zyxwvutsrqponmlkjihgfedcbaZYXWVUTSRQPONMLKJIHGFEDCBA"
                result_text = ""
                for s in text:
                    if s in str1:
                        if s != ' ':
                            result_text = result_text + str2[str1.index(s)]
                        else:
                            result_text = result_text + ' '
                    else:
                        result_text = '埃特巴什码只能对英文字母加密！'
            if result_text != "":
                self.Mainwindows.Ui.encode_Result_text.setText(result_text)
            else:
                self.Mainwindows.Ui.encode_Result_text.setText ('加密失败!')
        except Exception as e:
            self.Mainwindows.Ui.encode_Result_text.setText((e))
            # QMessageBox.critical(self,'Error',str(e))
            # print(str(e))
            pass

    def VigenereEncrypto(self,text):
        try:
            self.dialog.close()
            key = self.WChild.key.text()
            ptLen = len(text)
            keyLen = len(key)
            if keyLen == 0:
                self.Mainwindows.Ui.encode_Result_text.setText (str('请输入一个合法的key！'))
                return

            quotient = ptLen // keyLen  # 商
            remainder = ptLen % keyLen  # 余
            out = ""
            for i in range(0, quotient):
                for j in range(0, keyLen):
                    c = int((ord(text[i * keyLen + j]) - ord('a') + ord(key[j]) - ord('a')) % 26 + ord('a'))
                    # global output
                    out += chr(c)

            for i in range(0, remainder):
                c = int((ord(text[quotient * keyLen + i]) - ord('a') + ord(key[i]) - ord('a')) % 26 + ord('a'))
                # global output
                out += chr(c)

            if out != '':
                self.Mainwindows.Ui.encode_Result_text.setText (out)
            else:
                self.Mainwindows.Ui.encode_Result_text.setText ('加密失败！')
        except Exception as e:
            self.Mainwindows.Ui.encode_Result_text.setText (str(e))

    def sifang_encrypt(self,text):
        self.dialog.close()
        try:
            text =text.lower()
            key1 = self.WChild.Key1.text().upper()
            key2 = self.WChild.Key2.text().upper()
            matrix = "ABCDEFGHIJKLMNOPRSTUVWXYZ"
            pla = "abcdefghijklmnoprstuvwxyz"
            key1 = '[' + key1 + "]"
            key2 = '[' + key2 + "]"
            key1 = ''.join(collections.OrderedDict.fromkeys(key1))
            key2 = ''.join(collections.OrderedDict.fromkeys(key2))
            matrix1 = re.sub('[\[\]]', '', key1) + re.sub(key1, '', matrix)
            matrix2 = re.sub('[\[\]]', '', key2) + re.sub(key2, '', matrix)
            matrix_list1 = []
            matrix_list2 = []
            pla_list = []
            for i in range(0, len(matrix1), 5):
                matrix_list1.append(list(matrix1[i:i + 5]))
            for i in range(0, len(matrix2), 5):
                matrix_list2.append(list(matrix2[i:i + 5]))
            for i in range(0, len(pla), 5):
                pla_list.append(list(pla[i:i + 5]))
            pla = text.replace(' ', '')
            if len(pla) % 2 != 0:
                pla += 'x'
            cip = ""
            for i in range(0, len(pla), 2):
                data = pla[i:i + 2]
                # 两个子母中第一个字母位置
                first = self.find_index(data[0], pla_list)
                # 两个子母中第二个字母位置
                second = self.find_index(data[1], pla_list)
                return_cip = ""
                return_cip += matrix_list1[first[0]][second[1]]
                return_cip += matrix_list2[second[0]][first[1]]
                cip += return_cip
            if cip != '':
                self.Mainwindows.Ui.encode_Result_text.setText (cip)
            else:
                self.Mainwindows.Ui.encode_Result_text.setText ('加密失败！')

        except Exception as  e:
            self.Mainwindows.Ui.encode_Result_text("Key错误！")
            # print(str(e))
            pass

    def gcd(self, a, b):
        if (a < b):
            t = a
            a = b
            b = t

        while (0 != b):
            t = a
            a = b
            b = t % b
        return a

    def fangshe_encrypt(self,text):
        self.dialog.close()
        try:
            letter_list = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"  # 字母表
            key1 = self.WChild.Key1.text()
            key2 = self.WChild.Key2.text()
            # print(text,key2,key1)
            try:
                if (0 == int(key1.isdigit()) or 0 == int(key2.isdigit())):
                    self.Mainwindows.Ui.encode_Result_text.setText ('输入有误! 密钥为数字。')
                    return
                elif (self.gcd(int(key1), 26) != 1):
                    self.Mainwindows.Ui.encode_Result_text.setText ('输入有误! key1和26必须互素。')
                    return
                ciphertext = ""
                for ch in text:  # 遍历明文
                    if ch.isalpha():  # 明文是否为字母,如果是,则判断大小写,分别进行加密
                        if ch.isupper():
                            ciphertext += letter_list[(int(key1) * (ord(ch) - 65) + int(key2)) % 26]
                        else:
                            ciphertext += letter_list[(int(key1) * (ord(ch) - 97) + int(key2)) % 26].lower()
                    else:  # 如果密文不为字母,直接添加到密文字符串里
                        ciphertext += ch
                self.Mainwindows.Ui.encode_Result_text.setText(ciphertext)

            except Exception as e:
                print(e)
                self.Mainwindows.Ui.encode_Result_text.setText ('输入有误!')
        except Exception as  e:
            self.Mainwindows.Ui.encode_Result_text.setText ('加密失败!')
            # print(str(e))
            pass

    # 查询明文字母位置
    def find_index(self, x, pla_list):
        for i in range(len(pla_list)):
            for j in range(len(pla_list[i])):
                if pla_list[i][j] == x:
                    return i, j

    def zhalanEncrypto(self,plain):
        self.dialog.close()
        try:
            n = int(self.WChild_zhalan.key.text())
            ans = ''
            for i in range(n):
                for j in range(int(plain.__len__() / n + 0.5)):
                    try:
                        ans += plain[j * n + i]
                    except:
                        pass
        except:
            ans = "请输入正确的分组！"
        if ans != '':
            self.Mainwindows.Ui.encode_Result_text.setText(str(ans))
        else:
            self.Mainwindows.Ui.encode_Result_text.setText(str("加密失败"))
    # decrypt
    def decrypt(self, decrypt_type,text):
        try:
            text =text.strip()
            result_text = ''
            if text == '':
                self.Mainwindows.Ui.encode_Result_text.setText ('请输入一个源字符串！')
                return

            elif decrypt_type == 'Rot13':
                PAIRS = {
                    "a": "n", "b": "o", "c": "p", "d": "q", "e": "r",
                    "f": "s", "g": "t", "h": "u", "i": "v", "j": "w",
                    "k": "x", "l": "y", "m": "z", "n": "a", "o": "b",
                    "p": "c", "q": "d", "r": "e", "s": "f", "t": "g",
                    "u": "h", "v": "i", "w": "j", "x": "k", "y": "l",
                    "z": "m", "A": "N", "B": "O", "C": "P", "D": "Q",
                    "E": "R", "F": "S", "G": "T", "H": "U", "I": "V",
                    "J": "W", "K": "X", "L": "Y", "M": "Z", "N": "A",
                    "O": "B", "P": "C", "Q": "D", "R": "E", "S": "F",
                    "T": "G", "U": "H", "V": "I", "W": "J", "X": "K",
                    "Y": "L", "Z": "M"
                }
                result_text = "".join(PAIRS.get(c, c) for c in text)
            elif decrypt_type == '凯撒密码':
                t = ""
                for c in text:
                    if 'a' <= c <= 'z':  # str是可以直接比较的
                        t += chr(ord('a') + ((ord(c) - ord('a')) - 3) % 26)
                    elif 'A' <= c <= 'Z':
                        t += chr(ord('A') + ((ord(c) - ord('A')) - 3) % 26)
                    else:
                        t += c
                result_text = t
            elif decrypt_type == '栅栏密码':
                for n in range(2, text.__len__() - 1):
                    ans = ''
                    for i in range(n):
                        for j in range(int(text.__len__() / n + 0.5)):
                            try:
                                ans += text[j * n + i]
                            except:
                                pass
                    result_text += "分为%s栏，解密结果为:%s\n" % (n, ans)
            elif decrypt_type == '培根密码':
                return_str = ''
                dicts = {'aabbb': 'H', 'aabba': 'G', 'baaab': 'R', 'baaaa': 'Q', 'bbaab': 'Z', 'bbaaa': 'Y',
                         'abbab': 'N',
                         'abbaa': 'M', 'babaa': 'U', 'babab': 'V', 'abaaa': 'I', 'abaab': 'J', 'aabab': 'F',
                         'aabaa': 'E',
                         'aaaaa': 'A', 'aaaab': 'B', 'baabb': 'T', 'baaba': 'S', 'aaaba': 'C', 'aaabb': 'D',
                         'abbbb': 'P',
                         'abbba': 'O', 'ababa': 'K', 'ababb': 'L', 'babba': 'W', 'babbb': 'X'}
                sums = len(text)
                j = 5  ##每5个为一组
                for i in range(int(sums / j)):
                    result = text[j * i:j * (i + 1)].lower()
                    return_str += str(dicts[result], )
                result_text = return_str
            elif decrypt_type == '摩斯密码':
                dict = {'.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D',
                        '.': 'E', '..-.': 'F', '--.': 'G', '....': 'H',
                        '..': 'I', '.---': 'J', '-.-': 'K', '.-..': 'L',
                        '--': 'M', '-.': 'N', '---': 'O', '.--.': 'P',
                        '--.-': 'Q', '.-.': 'R', '...': 'S', '-': 'T',
                        '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X',
                        '-.--': 'Y', '--..': 'Z', '.----': '1', '..---': '2',
                        '...--': '3', '....-': '4', '.....': '5', '-....': '6',
                        '--...': '7', '---..': '8', '----.': '9', '-----': '0',
                        '..--..': '?', '-..-.': '/', '-.--.-': '()', '-....-': '-',
                        '.-.-.-': '.'
                        }
                msg = ''
                s = text.split(' ')
                for item in s:
                    if item != '' and item != ' ':
                        msg += (dict[item])
                result_text = msg
            elif decrypt_type == '移位密码':
                caseS1=''
                inputStr = text
                #
                result = ''
                for j in range(26):
                    result_list = []
                    for i, num in zip(inputStr, range(len(inputStr))):
                        # print(i)
                        if i.islower:
                            caseS1 = string.ascii_lowercase * 2
                        if i in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
                            caseS1 = string.ascii_uppercase * 2
                        status = caseS1.find(i)
                        if status != -1:
                            result_list.append(caseS1[status + j])
                        else:
                            result_list.append(inputStr[num])
                    text2 = ("".join(result_list), "向右偏移了{}位".format(j))
                    result += text2[0] + ' ' + text2[1] + '\n'
                result_text = result
            elif decrypt_type == '云影密码':
                other_letters = []
                for s in text:
                    if not ['0', '1', '2', '4', '8'].count(s):
                        other_letters.append(s)
                if other_letters:
                    result_text = '加密字符串内只能包含0、1、2、4、8'
                else:
                    charList = [chr(i) for i in range(ord('A'), ord('Z') + 1)]
                    ret = []
                    plaintext = [i for i in text.split('0')]
                    for i in plaintext:
                        tmp = 0
                        for j in range(len(i)):
                            tmp += int(i[j])
                        ret.append(charList[tmp - 1])
                    result_text = ''.join(ret)
            elif decrypt_type == '当铺密码':
                mapping_data = {'田': 0, '由': 1, '中': 2, '人': 3, '工': 4, '大': 5, '王': 6, '夫': 7, '井': 8, '羊': 9}
                result_text = ''.join(map(lambda x: str(mapping_data[x]), text))
            elif decrypt_type == '四方密码':
                self.WChild = Ui_KEY2()
                self.dialog = QtWidgets.QDialog()
                self.WChild.setupUi(self.dialog)
                self.dialog.show()
                self.WChild.enter.clicked.connect(lambda :self.sifang_decrypt(text))
                return 0
            elif decrypt_type == '仿射密码':
                self.WChild = Ui_KEY2()
                self.dialog = QtWidgets.QDialog()
                self.WChild.setupUi(self.dialog)
                self.dialog.show()
                self.WChild.enter.clicked.connect(lambda:self.fangshe_decrypt(text))
                return 0

            elif decrypt_type == '维吉尼亚密码':
                self.WChild = Ui_KEY1()
                self.dialog = QtWidgets.QDialog()
                self.WChild.setupUi(self.dialog)
                self.dialog.show()
                self.WChild.keyenter.clicked.connect(lambda :self.VigenereDecrypto(text))
                return 0
            elif decrypt_type == '埃特巴什码':
                str1 = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
                str2 = "zyxwvutsrqponmlkjihgfedcbaZYXWVUTSRQPONMLKJIHGFEDCBA"
                result_text = ""
                for s in text:
                    if s != ' ':
                        result_text = result_text + str1[str2.index(s)]
                    else:
                        result_text = result_text + ' '
            if result_text != "":
                self.Mainwindows.Ui.encode_Result_text.setText (result_text)
            else:
                self.Mainwindows.Ui.encode_Result_text.setText  ('解密失败！')
        except Exception as e:
            self.Mainwindows.Ui.encode_Result_text.setText  (str(e))
            # QMessageBox.critical(self,'Error',str(e))
            pass
            # print(str(e))

    def VigenereDecrypto(self,message):
        try:
            self.dialog.close()
            letter_list = string.ascii_uppercase
            letter_list2 = string.ascii_lowercase
            key = self.WChild.key.text()
            if len(key) == 0:
                return (str('请输入一个合法的key！'))

            key_list = []
            for i in key:
                key_list.append(ord(i.upper()) - 65)
            plaintext = ""
            flag = 0
            for cipher in message:
                if flag % len(key_list) == 0:
                    flag = 0
                if cipher.isalpha():
                    if cipher.isupper():
                        plaintext += letter_list[(ord(cipher) - 65 - key_list[flag]) % 26]
                        flag += 1
                    if cipher.islower():
                        plaintext += letter_list2[(ord(cipher) - 97 - key_list[flag]) % 26]
                        flag += 1
                else:
                    plaintext += cipher
            if plaintext != '':
                self.Mainwindows.Ui.encode_Result_text.setText  (plaintext)
            else:
                self.Mainwindows.Ui.encode_Result_text.setText ('解密失败！')
        except Exception as e:
            self.Mainwindows.Ui.encode_Result_text.setText  (str(e))

    def sifang_decrypt(self,text):
        self.dialog.close()
        try:
            # print(1)
            text = text.upper()
            key1 = self.WChild.Key1.text().upper()
            key2 = self.WChild.Key2.text().upper()
            matrix = "ABCDEFGHIJKLMNOPRSTUVWXYZ"
            pla = "abcdefghijklmnoprstuvwxyz"
            key1 = '[' + key1 + "]"
            key2 = '[' + key2 + "]"
            key1 = ''.join(collections.OrderedDict.fromkeys(key1))
            key2 = ''.join(collections.OrderedDict.fromkeys(key2))
            matrix1 = re.sub('[\[\]]', '', key1) + re.sub(key1, '', matrix)
            matrix2 = re.sub('[\[\]]', '', key2) + re.sub(key2, '', matrix)
            matrix_list1 = []
            matrix_list2 = []
            pla_list = []
            # print(matrix1)
            for i in range(0, len(matrix1), 5):
                matrix_list1.append(list(matrix1[i:i + 5]))
            for i in range(0, len(matrix2), 5):
                matrix_list2.append(list(matrix2[i:i + 5]))
            for i in range(0, len(pla), 5):
                pla_list.append(list(pla[i:i + 5]))
            cip = text.replace(' ', '')
            result = ''
            for i in range(0, len(cip), 2):
                letter = cip[i:i + 2]
                # 两个子母中第一个字母位置
                first = self.find_index1(letter[0], matrix_list1)

                # 两个子母中第二个字母位置
                second = self.find_index2(letter[1], matrix_list2)

                return_pla = ""
                return_pla += pla_list[first[0]][second[1]]
                return_pla += pla_list[second[0]][first[1]]
                result += return_pla
            if result != '':
                self.Mainwindows.Ui.encode_Result_text.setText (result)
            else:
                self.Mainwindows.Ui.encode_Result_text.setText ('解密失败！')

        except Exception as e:
            # print(str(e))
            pass

    # 求逆元函数
    def GetInverse(self, a, m):
        for i in range(m):
            if (1 == (a * i) % m):
                return i
        return a

    def fangshe_decrypt(self,text):
        self.dialog.close()
        try:
            key1 = self.WChild.Key1.text()
            key2 = self.WChild.Key2.text()
            try:
                if (0 == int(key1.isdigit()) or 0 == int(key2.isdigit())):
                    self.Mainwindows.Ui.encode_Result_text.setText('输入有误! 密钥为数字。')
                    return
                elif (self.gcd(int(key1), 26) != 1):
                    key1_list = []
                    result = ''
                    for i in range(0, int(key1)):
                        if self.gcd(i, 26) == 1:
                            key1_list.append(i)
                    for z in key1_list:
                        result += 'key1:%s' % z + '   明文:' + str(self.fangshe_getdecrypt(int(z), int(key2),text)) + '\n'
                    self.Mainwindows.Ui.encode_Result_text.setText('输入有误! key1和26必须互素。以下为爆破key1的结果\n' + result)
                    return 0
                else:
                    self.Mainwindows.Ui.encode_Result_text.setText(self.fangshe_getdecrypt(int(key1), int(key2),text))
            except:
                self.Mainwindows.Ui.encode_Result_text.setText('输入有误!')
                return

        except Exception as e:
            self.Mainwindows.Ui.Result_text.setText('解密失败。')
            # print(str(e))
            pass

    def fangshe_getdecrypt(self,key1,key2,text):
        try:
            letter_list = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"  # 字母表
            plaintext = ""
            for ch in text:  # 遍历密文
                if ch.isalpha():  # 密文为否为字母,如果是,则判断大小写,分别进行解密
                    if ch.isupper():
                        plaintext += letter_list[self.GetInverse(key1, 26) * (ord(ch) - 65 - key2) % 26]
                    else:
                        plaintext += letter_list[self.GetInverse(key1, 26) * (ord(ch) - 97 - key2) % 26].lower()
                else:  # 如果密文不为字母,直接添加到明文字符串里
                    plaintext += ch
            return  plaintext
        except:
            return
    # 查询两个密文字母位置
    def find_index1(self, x, matrix_list1):
        for i in range(len(matrix_list1)):
            for j in range(len(matrix_list1[i])):
                if matrix_list1[i][j] == x:
                    return i, j

    def find_index2(self, y, matrix_list2):
        for k in range(len(matrix_list2)):
            for l in range(len(matrix_list2[k])):
                if matrix_list2[k][l] == y:
                    return k, l

    # Binary
    def Binary(self, Binary_type,text):
        try:
            result_text = ''
            if text == '':
                self.Mainwindows.Ui.encode_Result_text.setText ('请输入一个源字符串！')
                return
            elif not text.isdigit():
                self.Mainwindows.Ui.encode_Result_text.setText ('请输入一个数字！')
                return

            elif  Binary_type == '任意进制转换':

                self.Binary_dialog = Ui_Binary()
                self.dialog = QtWidgets.QDialog()
                self.Binary_dialog.setupUi(self.dialog)
                self.dialog.show()
                self.Binary_dialog.enter.clicked.connect(lambda:self.Binary_conversion(text))
                return
            all_text = text.split(" ")
            all_result = ''
            for text in all_text:
                if text == "":
                    break
                if Binary_type == '2->8':
                    try:
                        result = int(text, 2)
                        result_text = str(oct(result))
                    except:
                        self.Mainwindows.Ui.encode_Result_text.setText('您输入的不是二进制！')
                        return
                elif Binary_type == '2->10':
                    try:
                        result = int(text, 2)
                        result_text = str(result)
                    except:
                        self.Mainwindows.Ui.encode_Result_text.setText('您输入的不是二进制！')
                        return
                elif Binary_type == '2->16':
                    try:
                        result_text = str(hex(int(text, 2)))
                    except:
                        self.Mainwindows.Ui.encode_Result_text.setText('您输入的不是二进制！')
                        return
                elif Binary_type == '8->2':
                    try:
                        result = int(text, 8)
                        result_text = str(bin(result))
                    except:
                        self.Mainwindows.Ui.encode_Result_text.setText('您输入的不是八进制！')
                        return
                elif Binary_type == '8->10':
                    try:
                        result = int(text, 8)
                        result_text = str(result)
                    except:
                        self.Mainwindows.Ui.encode_Result_text.setText('您输入的不是八进制！')
                        return
                elif Binary_type == '8->16':
                    try:
                        result = int(text, 8)
                        result_text = str(hex(result))
                    except:
                        self.Mainwindows.Ui.encode_Result_text.setText('您输入的不是八进制！')
                        return
                elif Binary_type == '10->2':
                    try:
                        s = int(text)
                        result_text = str(bin(s))
                    except:
                        self.Mainwindows.Ui.encode_Result_text.setText('您输入的不是十进制！')
                        return
                elif Binary_type == '10->8':
                    try:
                        s = int(text)
                        result_text = str(oct(s))
                    except:
                        self.Mainwindows.Ui.encode_Result_text.setText('您输入的不是十进制！')
                        return
                elif Binary_type == '10->16':
                    try:
                        s = int(text)
                        result_text = str(hex(s))
                    except:
                        self.Mainwindows.Ui.encode_Result_text.setText('您输入的不是十进制！')
                        return
                elif Binary_type == '16->2':
                    try:
                        result_text = str(bin(int(text, 16)))
                    except:
                        self.Mainwindows.Ui.encode_Result_text.setText('您输入的不是十六进制！')
                        return
                elif Binary_type == '16->8':
                    try:
                        result = int(text, 16)
                        result_text = str(oct(result))
                    except:
                        self.Mainwindows.Ui.encode_Result_text.setText('您输入的不是十六进制！')
                        return
                elif Binary_type == '16->10':
                    try:
                        result = int(text, 16)
                        result_text = str(result)
                    except:
                        self.Mainwindows.Ui.encode_Result_text.setText('您输入的不是十六进制！')
                        return
                all_result = all_result + result_text + ' '
            all_result = str(all_result).replace('0o', '').replace('0x', '').replace('0b', '')
            self.Mainwindows.Ui.encode_Result_text.setText (all_result)
        except Exception as e:
            self.Mainwindows.Ui.encode_Result_text.setText (str(e))
            pass

    def Binary_conversion(self,text):
        try:
            return_Data = ''
            self.dialog.close()
            if self.Binary_dialog.Source.text() != '' and self.Binary_dialog.result.text() != '':
                # print(text)
                from_ = int(self.Binary_dialog.Source.text())
                to_ = int(self.Binary_dialog.result.text())
                # from_进制转换为十进制
                ten_num = sum([int(i) * from_ ** n for n, i in enumerate(text[::-1])])
                # print(ten_num)
                # 十进制转换为to_进制
                a = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 'A', 'b', 'C', 'D', 'E', 'F']
                b = []
                while True:
                    s = ten_num // to_  # 商
                    y = ten_num % to_  # 余数
                    b = b + [y]
                    if s == 0:
                        break
                    ten_num = s
                b.reverse()
                for i in b:
                    return_Data += str(a[i])
                self.Mainwindows.Ui.encode_Result_text.setText (return_Data)
        except Exception as e:
            self.Mainwindows.Ui.encode_Result_text.setText ("转换失败！")








    # 文件打开对话框
    def file_open(self, type):
        fileName, selectedFilter = QFileDialog.getOpenFileName(None, (r"上传文件"), '', type)
        return (fileName)  # 返回文件路径

    # 保存文件对话框
    def file_save(self, filename,type):
        fileName, filetype = QFileDialog.getSaveFileName(None, (r"保存文件"), (filename),type)
        return fileName