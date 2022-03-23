# log4j2-scan
## 工具简介
log4j2-scan是一款利用浏览器爬虫爬取网站所有链接，并替换参数值为jndi形式，旨在遍历所有链接发现log4j2漏洞的工具。  


## 工作流程
1. 程序的工作流是利用rad爬取网站所有链接
    + 自动适配操作系统下载rad程序
2. 替换值为log4j2漏洞的payload
    + 更改请求中refer、agent值为payload
    + 更改GET型请求中'='号后的值为payload;
    + 更改POST型请求中data数据包中'=''、':'(json格式)后的值为payload
3. 将替换好的请求进行重放。
    + 如未定义payload, 脚本将自动从dnglog获取。
    + 如果是采用默认的dnslog为接收站点，那么将每重放十次检测一次dnslog。（考虑dnslog请求太多会被封禁）
    + 如自定义接收站点，将不进行检测。
     

## 运行参数
- 需要注意的是，必须安装有chrome才可以运行，不支持firefox等。 如chrome不是默认位置，须在rad_config.yml文件中指定chrome路径。
- payload值默认自动从dnslog获取，但是因平台问题无法访问时，程序会提示错误。用户可以自定义其他站点或ip，如http://ceye.io/
```
             _                _  _   _ ____      ____
    | |    ___   __ _| || | (_)___ \    / ___|  ___ __ _ _ __  _ __   ___ _ __
    | |   / _ \ / _` | || |_| | __) |___\___ \ / __/ _` | '_ \| '_ \ / _ \ '__|
    | |__| (_) | (_| |__   _| |/ __/_____|__) | (_| (_| | | | | | | |  __/ |
    |_____\___/ \__, |  |_|_/ |_____|   |____/ \___\__,_|_| |_|_| |_|\___|_|
                |___/     |__/     by jshahjk@163.com. Illegal use is prohibited.

rad_windows_amd64.exe
usage: scan_with_rad.py [-h] [-u URL] [-f FILE] [-c CHROME_PATH] [-p PAYLOAD]

optional arguments:
  -h, --help            show this help message and exit
  -u URL, --url URL     Check a single URL.
  -f FILE, --file FILE  file containing url.
  -c CHROME_PATH        Specify the chrome path.
  -p PAYLOAD, --payload PAYLOAD
                        Specify the payload like ${jndi:ldap://xx}.

```



运行命令：
```
python scan_with_rad.py -u www.hao24.com
python scan_with_rad.py -p mh7av.ceye.io -u www.xxxx.com
```




## 其他
之前计划使用的crawlergo，但是在尝试使用docker集成时发现crawlergo工作不正常。 所以crawlergo版本的暂时搁浅了，哪位大佬如能解决请赐教下。


