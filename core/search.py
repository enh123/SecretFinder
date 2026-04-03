import os
import signal
import sys
from concurrent.futures.thread import ThreadPoolExecutor

import requests
from colorama import Fore, init
from tqdm import tqdm

from modules import config
from modules import find_subdomain, find_param, find_path

init(autoreset=True)  # strip=False 表示不移除 ANSI 转义序列。
requests.packages.urllib3.disable_warnings()


class Search:
    def __init__(self):
        self.url = config.get_args("url")
        self.url_list = config.get_url_list()
        self.proxy = config.get_args("proxy")
        self.threads = config.get_args("threads")
        self.timeout = config.get_args("timeout")
        self.pattern_description = config.get_pattern_description()
        self.headers = config.get_args("headers")
        self.domain_list = config.get_args("domain_list")
        self.domain = config.get_args("domain")
        self.data_dict = {pattern: {} for pattern, description in self.pattern_description}
        self._stop_flag = False
        # 注册信号处理
        signal.signal(signal.SIGINT, self._signal_handler)
        self.session = requests.session()

    def _signal_handler(self, signum, frame):
        """处理终止信号"""
        self._stop_flag = True
        print("\n" + Fore.RED + "正在强制终止...")
        os._exit(1)  # 立即终止进程

    def stdin_math_data(self):
        """从标准输入读取内容并扫描"""
        try:
            text = config.get_stdin_text()
        except:
            return
        if not text:
            return
        if "-po" in sys.argv or "--path-only" in sys.argv:
            find_path.find(text)
            return
        for pattern, description in self.pattern_description:
            try:
                data = pattern.findall(text)
                if data:
                    self.data_dict[pattern]["stdin"] = data
            except:
                pass
        find_subdomain.find(text)
        if "-path" in sys.argv or "--path" in sys.argv:
            find_path.find(text)

    def match_data(self, url, process_bar=None):
        if self._stop_flag:
            return  # 提前终止检查
        try:
            response = self.session.get(url.strip(), headers=self.headers, proxies=self.proxy, verify=False,
                                        timeout=self.timeout)
        except Exception as e:
            if self.url_list and not self.url:
                process_bar.update(1)
            return
        if "-po" in sys.argv or "--path-only" in sys.argv:
            find_path.find(response.text)
            if self.url_list:
                process_bar.update(1)
            return

        if response.text and response.status_code != 404:
            for pattern, description in self.pattern_description:
                try:
                    data = pattern.findall(response.text)
                    if data:
                        self.data_dict[pattern][url.strip()] = data
                except:
                    pass

            find_subdomain.find(response.text)
            if "-path" in sys.argv or "--path" in sys.argv:
                find_path.find(response.text)

            if self.url_list:
                process_bar.update(1)

    def print_result(self):
        is_None = True
        # data_dict={
        # pattern:{ url:[data,data],url:[data,data] },
        # pattern:{ url:[data,data],url:[data,data] }, ....
        # }
        for pattern, description in self.pattern_description:
            for url_data in self.data_dict[pattern]:
                if url_data != {}:
                    is_None = False
        if is_None and config.get_subdomain_list() and config.get_path_list():
            print("\n" + Fore.RED + "未找到敏感信息")

        for pattern, description in self.pattern_description:
            urls_data = self.data_dict[pattern]  # urls_data=[url:[data,data],url:[data,data]]
            if urls_data:
                print(f"\n{Fore.YELLOW}{description}:")

            for url, data in urls_data.items():
                if description=="upload form":
                    print(Fore.CYAN + url)
                    continue
                else:
                    print(Fore.CYAN + "result from: " + url)

                for data_item in set(data):
                    print(f"{Fore.RED}{data_item}")
                print()  # 输出换行
        if config.get_subdomain_list():
            print('\n' + Fore.YELLOW + "子域名:")
            for subdomain in config.get_subdomain_list():
                print(f"{Fore.RED}{subdomain}")

        if config.get_path_list():
            if "--path" not in sys.argv and "-po" not in sys.argv:
                print('\n' + Fore.YELLOW + "路径:")
            for path in config.get_path_list():
                print(f"{Fore.RED}{path}")
        else:
            if "--path" in sys.argv or "-po" in sys.argv:
                print(Fore.RED + "未找到任何路径")

    def multi_thread(self):
        with tqdm(total=len(self.url_list), desc="process",
                  bar_format="{l_bar}{bar}{n_fmt}/{total_fmt} time: [{elapsed}]") as process_bar:
            with ThreadPoolExecutor(max_workers=self.threads, ) as executor:
                future_list = []
                for url in self.url_list:
                    future = executor.submit(self.match_data, url, process_bar)
                    future_list.append(future)
                for future in future_list:
                    future.result()


def main():
    search = Search()

    args = sys.argv
    get_key = "-key" in args or "--key" in args
    get_value = "-value" in args or "--value" in args
    if not search.url and search.url_list:
        if get_key and not get_value:
            key_list, _ = find_param.main()
            for key in key_list:
                key = key.strip()
                if key:
                    print(Fore.RED + key)
            sys.exit()

        if get_value and not get_key:
            _, value_list = find_param.main()
            for value in value_list:
                value = value.strip()
                if value:
                    print(Fore.RED + value)
            sys.exit()



    if search.url and not search.url_list:
        search.match_data(search.url)
    if not search.url and search.url_list:
        search.multi_thread()
    if "-s" in sys.argv or "--stdin" in sys.argv or config.get_stdin_text():
        search.stdin_math_data()
    search.print_result()
