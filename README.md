SecretFinder 敏感信息搜索工具

用法:

py -3 main.py -u http://baidu.com

py -3 main.py -f url.txt -t 10 --proxy="http://127.0.0.1:8080"



使用技巧:

 katana -d 5 -jc -kf all -s breadth-first -timeout 15 -retry 2 -headless -nos -automatic-form-fill -u urls.txt  >> all_urls.txt

 grep -E '\.js$|\.json$|\.config$|\.log$|\.txt$|\.sql$|\.env$|\.xml$' all_urls.txt >> secret_urls.txt

 httpx -l secret_urls.txt -mc 200 --retries 3 >> final_urls.txt

 py -3 main.py -f final_urls.tx -t 10 --proxy="http://127.0.0.1:8080" -d baidu.com,baidu.cn >> result.txt
 



参考了以下项目：
https://github.com/abhi-recon/jssecretscanner
https://github.com/gh0stkey/HaE
