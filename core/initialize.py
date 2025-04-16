import argparse

from modules import check, config


class InitializeClass:
    def process_args(self):
        parser = argparse.ArgumentParser()
        parser.add_argument("-u", "--url", dest="url", help="指定一个url", required=False)
        parser.add_argument("-f", "--file", dest="file", help="指定一个url文件", required=False)
        parser.add_argument("-H", dest="headers",
                            help="添加headers,可连续使用多个-H指定多个请求头,例如-H \"Cookie: xxxx\" -H \"User-Agent: xxx\"",
                            action="append", required=False)
        parser.add_argument("-d", "--domain", dest="domain",
                            help="提供主域名用于抓取相应包中的子域名,可以指定多个,用逗号分隔,例如-d baidu.com,baidu.cn",
                            required=False)
        parser.add_argument("-timeout", "--timeout", dest="timeout", help="请求最长等待时间", required=False,
                            default="25")
        parser.add_argument("-t", "--threads", dest="threads", type=int, help="设置线程数,默认为10个线程", default=10)
        parser.add_argument("-p", "--proxy", "-proxy", dest="proxy", help="设置代理,例如:--proxy=http://127.0.0.1:8080",
                            required=False)
        args = parser.parse_args()

        if args.url:
            config.set_value("url", args.url)

        if args.file:
            config.set_value("file", args.file)

        if args.headers:
            config.set_value("headers", args.headers)

        if args.domain:
            config.set_value("domain", args.domain)

        if args.timeout:
            config.set_value("timeout", args.timeout)

        if args.threads:
            config.set_value("threads", args.threads)
        else:
            config.set_value("threads", 10)

        if args.proxy:
            config.set_value("proxy", {"http": f"{args.proxy}", "https": f"{args.proxy}"})

        if args.output_file_name:
            config.set_value("output_file_name", args.output_file_name)

    def check_all(self):
        check.check_args()
        if config.get_value("url") != None and config.get_value("file") == None:
            url = check.check_url_format(config.get_value("url").strip())
            config.set_value("url", url)

        if config.get_value("file") != None and config.get_value("url") == None:
            with open(config.get_value("file"), "r", encoding='utf-8') as file:
                url_list = []
                for url in file.readlines():
                    url_list.append(check.check_url_format(url.strip()))
                config.set_value("url_list", url_list)


def main():
    initialize_instance = InitializeClass()
    initialize_instance.process_args()
    initialize_instance.check_all()
