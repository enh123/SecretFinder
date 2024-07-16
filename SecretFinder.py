import re
import sys
import requests
import threading
from colorama import init, Fore
from tqdm import tqdm
import argparse
import pyfiglet

init(autoreset=True)
requests.packages.urllib3.disable_warnings()


class SecretFinder:
    def __init__(self, file, threads, proxy, output_filename):
        self.file = file
        self.threads = threads
        self.proxy = {"http": proxy}
        self.output_filename = output_filename
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8",
            "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
            "Accept-Encoding": "gzip, deflate",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "Priority": "u=0, i",
            "Te": "trailers"
        }
        self.patterns_descriptions = [
            (re.compile(r'api[key|_key|\\s+]+[a-zA-Z0-9_\\-]{5,100}'), "API key"),
            (re.compile(r'key-[0-9a-zA-Z]{32}'), "key"),
            (re.compile(r'[a-zA-Z0-9_-]*:[a-zA-Z0-9_\\-]+@github\\.com*'), "Github令牌"),
            (re.compile(
                r'eyJ[A-Za-z0-9_/\+\-]{10,}={0,2}\.[A-Za-z0-9_/\+\-\\]{15,}={0,2}\.[A-Za-z0-9_/\+\-\\]{10,}={0,2}'),
             "JWT令牌"),
            (re.compile(r'\bglsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8}\b'), "Grafana服务帐户令牌"),
            (re.compile(r'\bAKID[A-Za-z\d]{13,40}\b'), "腾讯云 AccessKey ID"),
            (re.compile(r'\bJDC_[0-9A-Z]{25,40}\b'), "京东云 AccessKey ID"),
            (re.compile(r'"''[A-Z0-9]{16}["'']'), "亚马逊 AccessKey ID"),
            (re.compile(r'\b(?:AKLT|AKTP)[a-zA-Z0-9]{35,50}\b'), "火山引擎 AccessKey ID"),
            (re.compile(r'\bAKLT[a-zA-Z0-9\-_]{16,28}\b'), "金山云 AccessKey ID"),
            (re.compile(r'\bAIza[0-9A-Za-z_\-]{35}\b'), "谷歌云 AccessKey ID"),
            (re.compile(r'\b[Bb]earer\s+[a-zA-Z0-9\-=._+/\\]{20,500}\b'), "Bearer Token"),
            (re.compile(r'\b[Bb]asic\s+[A-Za-z0-9+/]{18,}={0,2}\b'), "Basic Token"),
            (re.compile(
                r'["\'\[]*[Aa]uthorization["\'\]]*\s*[:=]\s*[\'"]?\b(?:[Tt]oken\s+)?[a-zA-Z0-9\-_+/]{20,500}[\'"]?'),
             "Auth Token"),
            (re.compile(
                r'-----\s*?BEGIN[ A-Z0-9_-]*?PRIVATE KEY\s*?-----[a-zA-Z0-9\/\n\r=+]*-----\s*?END[ A-Z0-9_-]*? PRIVATE KEY\s*?-----'),
             "PRIVATE KEY"),
            (re.compile(r'\b(glpat-[a-zA-Z0-9\-=_]{20,22})\b'), "Gitlab V2 Token"),
            (re.compile(r'\b((?:ghp|gho|ghu|ghs|ghr|github_pat)_[a-zA-Z0-9_]{36,255})\b'), "Github Token"),
            (re.compile(r'\bAPID[a-zA-Z0-9]{32,42}\b'), "腾讯云 API网关 APPKEY"),
            (re.compile(r'["''](wx[a-z0-9]{15,18})["'']'), "微信 公众号/小程序 APPID"),
            (re.compile(r'["''](ww[a-z0-9]{15,18})["'']'), "企业微信 corpid"),
            (re.compile(r'["''](gh_[a-z0-9]{11,13})["'']'), "微信公众号"),
            (re.compile(
                r'(?i)(?:admin_?pass|password|[a-z]{3,15}_?password|user_?pass|user_?pwd|admin_?pwd)\\?["\']*\\s*[:=]\\s*\\?["\'][a-z0-9!@#$%&*]{5,20}\\?["\']'),
             "杂项"),
            (re.compile(r'\bhttps://qyapi.weixin.qq.com/cgi-bin/webhook/send\?key=[a-zA-Z0-9\-]{25,50}\b'),
             "企业微信 webhook"),
            (re.compile(r'\bhttps://oapi.dingtalk.com/robot/send\?access_token=[a-z0-9]{50,80}\b'), "钉钉 webhook"),
            (re.compile(r'\bhttps://open.feishu.cn/open-apis/bot/v2/hook/[a-z0-9\-]{25,50}\b'), "飞书 webhook"),
            (re.compile(
                r'\bhttps://hooks.slack.com/services/[a-zA-Z0-9\-_]{6,12}/[a-zA-Z0-9\-_]{6,12}/[a-zA-Z0-9\-_]{15,24}\b'),
             "Slack webhook"),
            (re.compile(r'\beyJrIjoi[a-zA-Z0-9\-_+/]{50,100}={0,2}\b'), "Grafana API key"),
            (re.compile(r'\bglc_[A-Za-z0-9\-_+/]{32,200}={0,2}\b'), "Grafana cloud API token"),
            (re.compile(r'\bLTAI[A-Za-z\d]{12,30}\b'), "阿里云 AccessKeyID"),
            (re.compile(r'\b(?!(?:.*[\/.]))(?=(?:.*\d){2})[A-Za-z\d]{30}\b'), "阿里云 AccessSecretKey"),
            (re.compile(r'1[34578]\d{9}'), "手机号"),
            (re.compile(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.(?!png|jpg|gif)[a-zA-Z0-9-.]+'), "邮箱"),
            (re.compile(r'\d{6}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx]'), "身份证号码"),
            (re.compile(
                r'\b(?:VUE|APP|REACT)_[A-Z_0-9]{1,15}_(?:KEY|PASS|PASSWORD|TOKEN|APIKEY)"[:=]"(?:[A-Za-z0-9_\-]{15,50}|[a-z0-9/+]{50,100}==?)'),
             "杂项"),
            (re.compile(
                r'(?i)(password|passwd|pwd|username|uid|secret|osskey|admin|api|app_key|DB_USERNAME_SQLSRV|DB_PASSWORD_SQLSRV|DB_DATABASE_SQLSRV|accesskey|access_key|ALIYUN_OSS_ACCESS_KEY_SECRET|ALIYUN_OSS_ACCESS_KEY_ID|ALIYUN_SMS_ACCESS_KEY_ID|ALIYUN_SMS_ACCESS_KEY_SECRET|appid|accesstoken|appsecret|corpid|corpsecret|app_id|app_secret|T_access_token|t_access_token|secret|accessKeySecret|accessKeyId|aliosstoken)[\'"]?\s*[:=]\s*[\'"]?([0-9a-zA-Z]{2,})[\'"]?'),
             "杂项"),
            (re.compile(
                r'(?i)((access_key|access_token|admin_pass|admin_user|algolia_admin_key|algolia_api_key|alias_pass|alicloud_access_key|amazon_secret_access_key|amazonaws|ansible_vault_password|aos_key|api_key|api_key_secret|api_key_sid|api_secret|api\.googlemaps|apidocs|apikey|apiSecret|app_debug|app_id|app_key|app_log_level|app_secret|appkey|appkeysecret|application_key|appsecret|appspot|auth_token|authorizationToken|authsecret|aws_access|aws_access_key_id|aws_bucket|aws_key|aws_secret|aws_token|AWSSecretKey|b2_app_key|bashrc password|bintray_apikey|bintray_gpg_password|bintray_password|boto|ca_certs|cert|client_secret|client_secret_key|cloud_password|cloudflare_token|cloudfront_key_pair_id|cloudflare_secret|console_access_key|data|db_password|db_user|dbpass|discord_token|dynamodb_access_key|dynamodb_secret_key|dropbox_key|dropbox_secret|ebay_secret|ebay_token|elasticsearch_password|elasticsearch_username|facebook_app_id|facebook_secret|firebase_key|github_auth_token|github_password|github_user|gitee_access_token|glitch_pass|gpg_secret_key|grafana_api_key|grafana_secret|heroku_key|honeycode_token|jira_api_token|kafka_password|kafka_user|keycloak_secret|kubernetes_token|laravel_key|ldap_password|linode_api_key|mailchimp_key|mailgun_api_key|mailjet_api_key|mailjet_secret|mongodb_password|mongodb_uri|my_sql_pass|my_sql_user|oauth_key|okta_api_key|okta_secret|one_password_secret|openai_key|openweathermap_api_key|outlook_token|passphrase|personal_access_token|password|paypal_key|private_key|provider_token|pypi_password|redis_password|sendgrid_key|shopify_password|slack_token|smtp_password|smtp_user|stripe_api_key|stripe_secret_key|terraform_key|tiktok_access_token|twitter_api_key|twitter_secret|vcenter_password|vault_key|vault_pass|veracode_api_key|xero_api_key|yandex_api_key|zabbix_api_token|zenodo_access_token|zohocrm_api_key|zoho_oauth|zoho_password|zuora_api_key|zoho_api_key|api_key|access_key|access_key_secret|secret|key|token|API|KEY|TOKEN|user_name|Lodop_key)[\'"]?\s*[:=]\s*[\'"]?([0-9A-Za-z\-_.]{32,100})[\'"]?)(?=\s|$|")'),
             "杂项"),
            # 以下是secretfinder原项目的正则
            (re.compile(r'AIza[0-9A-Za-z-_]{35}'), "google_api"),
            (re.compile(r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}'), "firebase"),
            (re.compile(r'6L[0-9A-Za-z-_]{38}|^6[0-9a-zA-Z_-]{39}$'), "google_captcha"),
            (re.compile(r'ya29\.[0-9A-Za-z\-_]+'), "google_oauth"),
            (re.compile(r'A[SK]IA[0-9A-Z]{16}'), "amazon_aws_access_key_id"),
            (re.compile(r'amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'),
             "amazon_mws_auth_token"),
            (re.compile(r's3\.amazonaws.com[/]+|[a-zA-Z0-9_-]*\.s3\.amazonaws.com'), "amazon_aws_url"),
            (re.compile(
                r"([a-zA-Z0-9-\._]+\.s3\.amazonaws\.com|s3://[a-zA-Z0-9-\._]+|s3-[a-zA-Z0-9-\._\/]+|s3.amazonaws.com/[a-zA-Z0-9-\._]+|s3.console.aws.amazon.com/s3/buckets/[a-zA-Z0-9-\._]+)"),
             "amazon_aws_url2"),
            (re.compile(r'EAACEdEose0cBA[0-9A-Za-z]+'), "facebook_access_token"),
            (re.compile(r'basic [a-zA-Z0-9=:_\+\/-]{5,100}'), "authorization_basic"),
            (re.compile(r'bearer [a-zA-Z0-9_\-\.=:_\+\/]{5,100}'), "authorization_bearer"),
            (re.compile(r'SK[0-9a-fA-F]{32}'), "twilio_api_key"),
            (re.compile(r'AC[a-zA-Z0-9_\-]{32}'), "twilio_account_sid"),
            (re.compile(r'AP[a-zA-Z0-9_\-]{32}'), "twilio_app_sid"),
            (re.compile(r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}'), "paypal_braintree_access_token"),
            (re.compile(r'sq0csp-[0-9A-Za-z\-_]{43}|sq0[a-z]{3}-[0-9A-Za-z\-_]{22,43}'), "square_oauth_secret"),
            (re.compile(r'sqOatp-[0-9A-Za-z\-_]{22}|EAAA[a-zA-Z0-9]{60}'), "square_access_token"),
            (re.compile(r'sk_live_[0-9a-zA-Z]{24}'), "stripe_standard_api"),
            (re.compile(r'rk_live_[0-9a-zA-Z]{24}'), "stripe_restricted_api"),
            (re.compile(r'-----BEGIN RSA PRIVATE KEY-----'), "rsa_private_key"),
            (re.compile(r'-----BEGIN DSA PRIVATE KEY-----'), "ssh_dsa_private_key"),
            (re.compile(r'-----BEGIN EC PRIVATE KEY-----'), "ssh_dc_private_key",),
            (re.compile(r'-----BEGIN PGP PRIVATE KEY BLOCK-----'), "pgp_private_block"),
            (re.compile(r'ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*$'), "json_web_token"),
            (re.compile(r'"api_token":"(xox[a-zA-Z]-[a-zA-Z0-9-]+)"'), "slack_token"),
            (re.compile(r'[-]+BEGIN [^\s]+ PRIVATE KEY[-]+[\s]*[^-]*[-]+END [^\s]+ PRIVATE KEY[-]+'), "SSH_privKey"),
        ]
        self.matched_content = {pattern: {} for pattern, description in self.patterns_descriptions}

    def banner(self):
        title = pyfiglet.figlet_format("Secret Finder", font='standard')
        print(Fore.CYAN + title)

    def match_data(self, url, progress_bar=None):
        try:
            response = requests.get(url.strip(), headers=self.headers, proxies=self.proxy, verify=False, timeout=10)
            if response.status_code == 200:
                for pattern, description in self.patterns_descriptions:
                    matches = pattern.findall(response.text)
                    if matches:
                        self.matched_content[pattern][url.strip()] = matches
        except:
            pass

        if "-u" not in sys.argv and "-f" in sys.argv:
            progress_bar.update(1)

    def multiple_thread(self):
        thread_list = []
        with open(self.file, 'r', encoding='utf-8') as file:
            urls = file.readlines()
            with tqdm(total=len(urls), desc="Progress", unit="url") as progress_bar:
                for i in range(0, len(urls), self.threads):
                    for url in urls[i:i + self.threads]:
                        thread = threading.Thread(target=self.match_data, args=(url, progress_bar))
                        thread_list.append(thread)
                        thread.start()
                for thread in thread_list:
                    thread.join()

    def print_result(self):
        if '-o' in sys.argv or '--output' in sys.argv:
            outputfile = open(self.output_filename, 'a', encoding='utf-8')
        if self.matched_content:
            for pattern, description in self.patterns_descriptions:
                links_data = self.matched_content[pattern]
                if links_data:
                    print(f"\n{description}:")
                    if '-o' in sys.argv or '--output' in sys.argv:
                        outputfile.write(f"\n{description}:")
                    for link, matches in links_data.items():
                        print(f"result from: {link}:")
                        if '-o' in sys.argv or '--output' in sys.argv:
                            outputfile.write(f"\nresult from: {link}:\n")
                        for match in matches:
                            print(f"{Fore.RED}{match}")
                            if '-o' in sys.argv or '--output' in sys.argv:
                                outputfile.write(f"{match}\n")

        else:
            print("未找到任何敏感信息......")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-u", help="指定一个url", dest="url", required=False)
    parser.add_argument("-f", dest='file', required=False, help="指定一个url文件")
    parser.add_argument("-t", "-threads", "--threads", help="设置线程数,默认3个线程", dest="threads", required=False,
                        default=3, type=int)
    parser.add_argument("-p", "-proxy", "--proxy", dest="proxy", help="设置代理", required=False)
    parser.add_argument("-o", "--output", help="将结果输出", dest="output_filename", required=False)
    args = parser.parse_args()
    secretfinder = SecretFinder(args.file, args.threads, args.proxy, args.output_filename)
    secretfinder.banner()
    if "-u" in sys.argv and "-f" not in sys.argv:
        secretfinder.match_data(args.url)
    if "-f" in sys.argv and "-u" not in sys.argv:
        secretfinder.multiple_thread()
    secretfinder.print_result()


if __name__ == '__main__':
    main()
