import sys
import requests
from modules import config
import re

requests.packages.urllib3.disable_warnings()

def check_args():

    if config.get_value("url") ==None and config.get_value("file")==None :
        sys.exit("请指定一个url或url文件")

    if config.get_value("url")!=None and config.get_value("file")!=None:
        sys.exit("-u 和 -f 参数只能使用一个")

def check_url_format(url):
    def extract_port(url):
        try:
            match = re.search(r':(\d+)', url)
            if match:
                return int(match.group(1))
            else:
                return None
        except Exception as e:
            return None

    if not (url.startswith("http://") or url.startswith("https://")):
        try:
            port = extract_port(url)
            if port:
                if int(port) != 443:
                    url = "http://" + url
                else:
                    url = "https://" + url
        except:
            pass
    return url




