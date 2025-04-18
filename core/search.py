import os
import re
import signal
import sys
from concurrent.futures import ThreadPoolExecutor

import pyfiglet
import requests
from colorama import Fore, init
from tqdm import tqdm

from modules import config, find_param, find_path, find_subdomain

init(autoreset=True, strip=False)  # 添加 strip=False
requests.packages.urllib3.disable_warnings()

class Search:
    def __init__(self):
        self.url = config.get_value("url")
        self.url_list = config.get_value("url_list")
        self.domain = config.get_value("domain")
        self.threads = config.get_value("threads")
        self.proxy = config.get_value("proxy")
        self.output_file_name = config.get_value("output_file_name")
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0"
        }
        try:
            headers = config.get_value("headers")
            for header in headers:
                parts = header.split(':')
                key = parts[0].strip()
                value = parts[1].strip()
                if key and value:
                    self.headers[key] = value
        except Exception as e:
            pass

        self.session = requests.session()
        self.pattern_description = config.get_pattern_description()
        self.data_dict = {pattern: {} for pattern, description in self.pattern_description}

        self._stop_flag = False
        # 注册信号处理
        signal.signal(signal.SIGINT, self._signal_handler)

        self.subdomain_list = []

    def _signal_handler(self,):
        """处理终止信号"""
        self._stop_flag = True
        print("\n" + Fore.RED + "正在强制终止...")
        os._exit(1)  # 立即终止进程

    def match_data(self, url, process_bar=None):
        if self._stop_flag:
            return  # 提前终止检查
        try:
            response = self.session.get(url.strip(), headers=self.headers, proxies=self.proxy, verify=False, timeout=30)

        except Exception as e:
            if "-f" in sys.argv and "-u" not in sys.argv:
                process_bar.update(1)
            return
        if self._stop_flag:
            return

        if response.text and response.status_code!=404:
            for pattern, description in self.pattern_description:
                matched_data = pattern.findall(response.text)
                if matched_data:
                    self.data_dict[pattern][url.strip()] = matched_data

            find_path.find_path(response.text)
            find_subdomain.find_subdomain(response.text)

            if self.url and not self.url_list:

                if self.domain:
                    if ',' in self.domain:
                        domains = self.domain.split(',')

            if self.domain is not None and ('-d' in sys.argv or '--domain' in sys.argv):
                if ',' in self.domain:
                    domains = self.domain.split(',')
                    for domain in domains:
                        regex = r'(?:[a-zA-Z0-9_-]+\.)+' + domain
                        subdomains = re.findall(regex, response.text, re.IGNORECASE)
                        if subdomains:
                            for subdomain in subdomains:
                                self.subdomain_list.append(subdomain.strip())

        if "-f" in sys.argv and "-u" not in sys.argv:
            process_bar.update(1)

    def print_result(self):
        is_None = True
        for pattern, description in self.pattern_description:
            urls_data = self.data_dict[pattern]
            if urls_data != {}:  # 不为空
                is_None = False

        if is_None and not (config.get_subdomain_list() and config.get_path_list()):
            sys.exit("\n" + Fore.RED + "未找到敏感信息")

        for pattern, description in self.pattern_description:
            urls_data = self.data_dict[pattern]
            if urls_data:
                print(f"\n{Fore.YELLOW}{description}:")

            for url, matched_data in urls_data.items():
                print(Fore.CYAN + "result from: " + url + ":")

                for data in set(matched_data):
                    print(f"{Fore.RED}{data}")
                print()  # 输出换行

        if config.get_subdomain_list():
            print('\n' + Fore.YELLOW + "子域名:")
            for subdomain in config.get_subdomain_list():
                print(f"{Fore.RED}{subdomain}")

        if config.get_path_list():
            print('\n' + Fore.YELLOW + "路径:")
            for path in config.get_path_list():
                print(f"{Fore.RED}{path}")

    def muiltiple_thread(self):
        with tqdm(total=len(self.url_list), desc="process",
                  bar_format="{l_bar}{bar} {n_fmt}/{total_fmt} time [{elapsed}]") as process_bar:
            with ThreadPoolExecutor(max_workers=self.threads, ) as executor:
                future_list = []
                for url in self.url_list:
                    future = executor.submit(self.match_data, url, process_bar)
                    future_list.append(future)
                for future in future_list:
                    future.result()


def main():
    search = Search()
    if not search.url and search.url_list and ("-param" in sys.argv or "--param" in sys.argv):
        find_param.main()
        sys.exit()

    if search.url and not search.url_list:
        search.match_data(config.get_value("url"))
    if not search.url and search.url_list:
        search.muiltiple_thread()

    search.print_result()
