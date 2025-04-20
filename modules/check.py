import re
import sys
import pyfiglet
from colorama import Fore
from modules import config


def check_args():
    if not (config.get_args("url") or config.get_args("file")):
        sys.exit("请指定一个url或url文件")

    elif config.get_args("url") and config.get_args("file"):
        sys.exit("-u和-f不能同时使用")

    elif  config.get_args("url") and ("-param" in sys.argv or "--param" in sys.argv):
        sys.exit("-u 和 -param 不能同时使用,正确用法为 python3 main.py -f url.txt -param")


def check_url_format(url):
    if not (url.startswith("http://") or url.startswith("https://")):
            pattern = re.compile(r':(\d+)')
            try:
                port = int(pattern.search(url).group(1))
            except Exception as e:
                port=None
                pass
            if port:
                if int(port) != 443:
                    url = "http://" + url
                else:
                    url = "https://" + url
            else:
                url = "http://" + url

    return url

def banner():
    print(Fore.CYAN+pyfiglet.figlet_format("Secret Finder",font="standard"))

def main():
    check_args()
    url=config.get_args("url")
    if url:
        url=check_url_format(url)
        config.set_args("url",url if url else None)

    if config.get_args("file"):
        try:
            with open(config.get_args("file"),"r",encoding='utf-8') as file:
                url_list=[]
                for url in file.readlines():
                    url=check_url_format(url.strip())
                    if url:
                        url_list.append(url)
                if url_list:
                    config.set_url_list(url_list)
        except:
            pass
    banner()
