SecretFinder 渗透测试敏感信息搜索工具

用法一：
![{D6FD4B0C-9115-4E00-BE86-76AF7C5D144B}_mosaic(1)](https://github.com/user-attachments/assets/122b3aa9-9801-4ddd-a784-dbfb3134e728)
![{F2A64928-DFA2-4284-A9B5-7D2A333BC081}_mosaic](https://github.com/user-attachments/assets/2dabfad6-b7ed-48e8-addf-7948f8ba5cff)



用法二,不发送请求直接从url中提取参数和值：
![{5A5874BA-9839-41E8-90DB-17AFEA3EA572}](https://github.com/user-attachments/assets/60cef0ed-0454-402a-a9cf-dfdaad263d8d)

![{ED18343B-92D0-4298-BD2D-E491A30FD975}](https://github.com/user-attachments/assets/cc16f8ea-c2f7-402b-8a64-4a17bc12da4a)


可以匹配多种规则例如:
key=123456
key='123456'
key:123456
key:'123456'
'key':'123456'
'key' = '123456'


使用技巧:

 katana -d 5 -jc -kf all -s breadth-first -timeout 15 -retry 2 -headless -nos -automatic-form-fill -u urls.txt  >> all_urls.txt

 sort -u all_urls.txt -o all_urls.txt

 grep -E '\.js$|\.json$|\.config$|\.log$|\.txt$|\.sql$|\.env$|\.xml$' all_urls.txt >> secret_urls.txt

 httpx -l secret_urls.txt -mc 200 --retries 3 >> final_urls.txt

 py -3 main.py -f final_urls.txt -t 10 --proxy="http://127.0.0.1:8080" -d baidu.com,baidu.cn >> result.txt
 



参考了以下项目：
https://github.com/abhi-recon/jssecretscanner

https://github.com/gh0stkey/HaE
