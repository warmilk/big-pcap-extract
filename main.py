"""
author: warmilk
github: https://github.com/warmilk
"""

import os
import subprocess
import re
from bs4 import BeautifulSoup as BeautifulSoup


seq = ('name', 'CVE', 'tuples_protocol', 'tuples_src_ip')
strike = {}
strike = strike.fromkeys(seq)

Tshark_path = '"C:\\Program Files\\Wireshark\\tshark.exe"'

current_extract_index = '1' # 要提取的html和pcap的文件名


current_project_path = os.getcwd().replace('\\', '/')
source_html_path = ''.join([current_project_path, '/assets/' + current_extract_index + '.html'])
source_pcap_path = '.\\assets\\' + current_extract_index + '.pcap'


dist_folder_path = './dist' # 提取的pcap还有rules存放的根文件夹路径


"""
@:param is_has_level3: 是否存在二级目录
@:param table: table的html元素节点
"""
def anylsis_sigle_table(table, is_has_level3, strike_level1_path, strike_level2_path):
    sid = 0;
    tr_list = table.find('tbody').find_all('tr')
    for tr in tr_list:
        # --------------Strike name 开始------------------
        if not tr.select_one("td:nth-of-type(2)").find('a'): # 7.7.6.1.4.3. Exploits: Browser 的table会报错，因为存在三级目录，这里跳过，不打算继续分类了
            continue
        else:
            strike_name = tr.select_one("td:nth-of-type(2)").find('a').text.strip()
            strike['name'] = re.sub(r'\s', '_', strike_name).replace('<=_', '＜＝').replace('.', '·').replace(':', '：').replace('\'', '').replace('/', '-').replace('<', '＜').replace('"', '”').replace("'", "’").replace('>', '＞')
            # --------------Strike name 结束------------------

            # --------------Strike Reference 开始------------------
            strike_reference_td = tr.select_one("td:nth-of-type(4)>div>a")
            if (not strike_reference_td) or (strike_reference_td and strike_reference_td.contents[0].find("http://") != -1) or (strike_reference_td and strike_reference_td.contents[0].find("https://") != -1):
                strike['CVE'] = 'none'
                if is_has_level3 == 'true':
                    strike_file_full_path = ''.join([strike_level2_path, '/', strike['name'], '/', strike['name']])
                else:
                    strike_file_full_path = ''.join([strike_level1_path, '/', strike['name'], '/', strike['name']])
            else:
                strike['CVE'] = re.sub(r'\s', '', tr.select_one("td:nth-of-type(4)>div>a").contents[0].strip())
                if is_has_level3 == 'true':
                    strike_file_full_path = ''.join([strike_level2_path, '/', strike['name'], '/',  strike['CVE']])
                else:
                    strike_file_full_path = ''.join([strike_level1_path, '/', strike['name'], '/', strike['CVE']])
            # --------------Strike Reference 结束------------------

            # --------------Strike Tuples 开始------------------
            strike_tuples = tr.select_one("td:nth-of-type(6)>span").contents[0]
            strike['tuples_protocol'] = strike_tuples[0:strike_tuples.index(' ')] #查找第一个空格开始的地方
            strike['tuples_src_ip'] = strike_tuples[strike_tuples.index(' ') + 1:strike_tuples.index(':')]
            # --------------Strike Tuples 结束------------------
            sid = sid + 1
            # -------------------- 生成rules文件开始-------------------
            strike_rules_file = strike_file_full_path + ".rules"
            if not os.path.exists(strike_file_full_path + '/'):
                os.makedirs(strike_file_full_path)
                file = open(strike_rules_file, "w")
                file.write(''.join(
                    ['reject ', strike['tuples_protocol'].lower(), ' any any -> any any (msg:"',
                     strike_name,
                     '"; flow:established,to_server;', ' classtype:attempted-user;', 'sid:', str(sid), ';',
                     'rev:',
                     '0;', ')']))
                file.close()
            # -------------------- 生成rules文件结束-------------------
            # -------------------- 生成pcap文件开始-------------------
            strike_pcap_file = strike_file_full_path + '_' + current_extract_index + ".pcap"
            file = open(strike_pcap_file, "w")
            file.close()
            if strike['tuples_protocol'] != 'NULL':
                command = ''.join(
                    [Tshark_path, ' -2', ' -r ', source_pcap_path, ' -Y ', 'ip.addr==',
                     strike['tuples_src_ip'],
                     ' -w ',
                     strike_pcap_file])
                print('当前执行的命令是：', command)
                os.system(command)
            # -------------------- 生成pcap文件结束-------------------


def go():
    soup = BeautifulSoup(open(source_html_path), "lxml")
    h5_list = soup.find_all('h5')
    for h5 in h5_list:
        # -------------------- 生成【一级目录】开始-------------------
        level1_dict = h5.find('a').text.strip()
        level1_dict_name = re.sub(r'\s', '-', level1_dict[0:level1_dict.index(':')])
        level1_dict_count = level1_dict[level1_dict.index('/') + 1:len(level1_dict)]
        strike_level1_path = ''.join([dist_folder_path, '/', level1_dict_name, '（', level1_dict_count, '）'])
        if not os.path.exists(strike_level1_path + '/'):
            os.makedirs(strike_level1_path + '/')
        # -------------------- 生成【一级目录】结束-------------------
        try:
            h5_brother_2 = h5.find_next_sibling().find_next_sibling()
            if (not h5_brother_2) or (h5_brother_2 and h5_brother_2.name != 'h6'):
                # -------------------- 生成【一级目录】下的strike开始-------------------
                level1_table = h5.find_next_sibling('table')
                anylsis_sigle_table(level1_table, 'false', strike_level1_path, '')
                # -------------------- 生成【一级目录】下的strike结束-------------------
                print('没有二级目录')
            else:
                print('有二级目录，h5_brother_2为<h6>')
                level1_tr_list = h5.find_next_sibling().find('tbody').find_all('tr')
                # -------------------- 生成【一级目录】下的【二级目录】开始-------------------
                level1_section_count = len(level1_tr_list)  # 一级目录下面有多少种二级类目
                h6_list = h5.find_next_siblings('h6')[0:level1_section_count]
                for h6 in h6_list:
                    level2_dict = h6.find('a').text.strip()
                    level2_dict_count = level2_dict[level2_dict.index('/') + 1:len(level2_dict)]
                    level2_table = h6.find_next_sibling('table')
                    level2_dict_name = re.sub(r'\s', '-', level2_dict[level2_dict.index(':') + 2:level2_dict.rindex(' ')]).replace('(', '[').replace(')', ']')
                    strike_level2_path = ''.join([strike_level1_path, '/', level2_dict_name, '（', level2_dict_count, '）'])
                    if not os.path.exists(strike_level2_path + '/'):
                        os.makedirs(strike_level2_path + '/')
                    anylsis_sigle_table(level2_table, 'true', strike_level1_path, strike_level2_path)
                # -------------------- 生成【一级目录】下的【二级目录】结束-------------------

        except ValueError:
            print('出错了')


if __name__ == '__main__':
    go()

