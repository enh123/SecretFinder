import re
from colorama import Fore
from . import config

def main():
    key_list = []
    value_list = []
    url_list = config.get_value("url_list")
    if url_list is not None:
        for url in url_list:
            keys = re.findall(r'[?&]([0-9a-zA-Z_]+)=', url.strip())
            values = re.findall(r'=([0-9a-zA-Z_]*)', url.strip())
            for key in keys:
                if len(key) <= 25 and not key.isdigit():
                    key_list.append(key)
            for value in values:
                if len(value) <= 30 and not value.isdigit():
                    value_list.append(value)

    print(Fore.YELLOW + "----------------key----------------")
    for key in set(key_list):
        print(Fore.RED+key)

    print('\n' + Fore.YELLOW + "----------------value----------------")
    for value in set(value_list):
        print(Fore.RED+value)
