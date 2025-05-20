import argparse
import sys

from modules import config


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-u", "--url", dest="url", help="指定一个url", required=False, type=str)
    parser.add_argument("-f", "--file", dest="file", help="指定一个url文件", required=False, type=str)
    parser.add_argument("-H", dest="headers",
                        help="添加headers,可连续使用多个-H指定多个请求头,例如-H \"Cookie: xxxx\" -H \"User-Agent: xxx\"",
                        action="append", required=False, type=str)
    parser.add_argument("-d", "--domain", dest="domain",
                        help="提供主域名用于抓取相应包中的子域名,可以指定多个,用逗号分隔,例如-d baidu.com,baidu.cn",
                        required=False, type=str)
    parser.add_argument("-param", "--param",
                        help="不发起请求,提取url中的参数和值,与-f一起使用",
                        required=False, action="store_true")
    parser.add_argument("-path", "--path",
                        help="提取页面中的路径",
                        required=False, action="store_true")
    parser.add_argument("-timeout", "--timeout", dest="timeout", help="请求最长等待时间", required=False,
                        default=25, type=int)
    parser.add_argument("-t", "--threads", dest="threads", type=int, help="设置线程数,默认为10个线程", default=10)
    parser.add_argument("-p", "--proxy", "-proxy", dest="proxy", help="设置代理,例如:--proxy=http://127.0.0.1:8080",
                        required=False)
    args = parser.parse_args()

    config.set_args("url", args.url.strip() if args.url else None)

    config.set_args("file", args.file if args.file else None)

    if args.proxy:
        proxies = {"http": args.proxy, "https": args.proxy}
        config.set_args("proxy", proxies if proxies else None)
    if args.timeout:
        config.set_args("timeout", int(args.timeout) if args.timeout else 25)

    config.set_args("threads", args.threads if args.threads else None)

    if args.domain:
        if ',' in args.domain:
            domain_list = args.domain.split(",")
            config.set_args("domain_list", domain_list if domain_list else None)
        else:
            config.set_args("domain", args.domain)
    else:
        config.set_args("domain", None)

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0"
    }
    if args.headers:
        for header in args.headers:
            if ':' in header:
                try:
                    header_parts = header.split(':')
                    if len(header_parts) == 2:
                        headers[header_parts[0].strip()] = header_parts[1].strip()
                except Exception as e:
                    sys.exit(e)
    config.set_args("headers", headers)

def main():
    parse_args()
