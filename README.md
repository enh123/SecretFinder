更适合中国宝宝体质的SecretFinder~

本项目借鉴了该项目:https://github.com/abhi-recon/jssecretscanner

在该项目的基础上添加了很多正则和一些功能，包括SecretFinder的正则和wih的正则，还有各种密钥如appkey,corpid,corpsecret等等

由于wih没办法对指定的js文件进行扫描，并且SecretFinder也不是很好用，在尝试了很多的密钥查找工具之后感觉都不太好用所以就开发了这款工具

在这里贴一个wih windows版本的地址https://github.com/adysec/ARL/blob/3eb45fb09361fd4f713768542e07829d463fc707/tools/wih/wih_amd64.exe

用法:

py -3 SecretFinder -u http://baidu.com

py -3 SecretFinder -f url.txt -t 10 --proxy="http://127.0.0.1:8080" -o output.txt


建议配合以下两个工具使用
https://github.com/pingc0y/URLFinder 
https://github.com/deibit/cansina
