import re
import sys
from urllib.parse import urlparse, parse_qs

args_dict = {}
url_list = []
path_list = []
subdomain_list=[]

def set_args(key, value):
    try:
        if key:
            args_dict[key] = value if value is not None else None  # 处理 None 值
        else:
            raise ValueError("key不存在")
    except Exception as e:
        sys.exit(e)


def get_args( key):
    try:
        if key and args_dict[key]:
            return args_dict[key]
        else:
            return None
    except Exception as e:
        return None


def set_url_list(urllist):
    global url_list
    if urllist:
        url_list = urllist

def get_url_list():
    if url_list:
        return url_list
    else:
        return None

def set_subdomain(subdomain):
    if subdomain:
        subdomain_list.append(subdomain)
def get_subdomain_list():
    return set(subdomain_list)

def set_path(path):
    if path:
        path_list.append(path.strip())

def get_path_list():
    seen = set()
    result = []
    for path in path_list:
        parsed = urlparse(path)
        normalized_path = parsed.path.lower().rstrip('/')
        param_keys = tuple(sorted(parse_qs(parsed.query).keys()))
        dedup_key = (normalized_path, param_keys)

        if dedup_key not in seen:
            seen.add(dedup_key)
            result.append(path)
    return result


def get_pattern_description():
    pattern_description = [
        # 值不能带冒号和单双引号和反斜杠,值的长度为1-10
        (re.compile(r'''(?i)["']?User_Check_Codes["']?\s*[:=]\s*(?:(["'])([^:'"\\]{3,16})\1|([^:"'\s]{3,16}))'''),
         "User_Check_Codes"),

        # (re.compile(r'''(?i)["']?REMOTE_ADDR["']?\s*[:=]\s*(?:(["'])([^!@#$%^&*()_+:'"\\]{7,16})\1|([^"'\s]{7,16}))'''),"REMOTE_ADDR"),

        (re.compile(
            r'''\b(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\b'''),
         "ip 地址"),

        (re.compile(
            r'''(?i)["']?DOCUMENT_ROOT["']?\s*[:=]\s*(?:(["'])([^!@#$%^&*()_+:'"\\]{3,50})\1|([^!@#$%^&*()_+:'"\\\s]{3,50}))'''),
         "DOCUMENT_ROOT"),

        (re.compile(
            r'''(?i)["']?SCRIPT_FILENAME["']?\s*[:=]\s*(?:(["'])([^!@#$%^&*()_+:'"\\]{3,50})\1|([^!@#$%^&*()_+:'"\\\s]{3,50}))'''),
         "SCRIPT_FILENAME"),

        (re.compile(r'''(?i)["']?APP_KEY["']?\s*[:=]\s*(?:(["'])([^'"\\]{4,50})\1|([^"'\s]{4,50}))'''), "APP_KEY"),

        (re.compile(r'''(?i)["']?appkey["']?\s*[:=]\s*(?:(["'])([^'"\\]{4,50})\1|([^"'\s]{4,50}))'''), "appkey"),

        (re.compile(r'''(?i)["']?DB_DATABASE_SQLSRV["']?\s*[:=]\s*(?:(["'])([^'"\\]{4,50})\1|([^"'\s]{3,30}))'''),
         "DB_DATABASE_SQLSRV"),

        (re.compile(r'''(?i)["']?DB_USERNAME_SQLSRV["']?\s*[:=]\s*(?:(["'])([^'"\\]{4,50})\1|([^"'\s]{3,30}))'''),
         "DB_USERNAME_SQLSRV"),

        (re.compile(r'''(?i)["']?DB_PASSWORD_SQLSRV["']?\s*[:=]\s*(?:(["'])([^'"\\]{4,25})\1|([^"'\s]{4,25}))'''),
         "DB_PASSWORD_SQLSRV"),

        (re.compile(r'''(?i)["']?REDIS_PASSWORD["']?\s*[:=]\s*(?:(["'])([^'"\\]{3,20})\1|([^"'\s]{3,20}))'''),
         "REDIS_PASSWORD"),

        (re.compile(
            r'''(?i)["']?ALIYUN_OSS_ACCESS_KEY_ID["']?\s*[:=]\s*(?:(["'])([^!@#$%^&*()'"\\]{16,64})\1|([^!@#$%^&*()'"\\\s]{4,50}))'''),
         "ALIYUN_OSS_ACCESS_KEY_ID"),

        (re.compile(
            r'''(?i)["']?ALIYUN_OSS_ACCESS_KEY_SECRET["']?\s*[:=]\s*(?:(["'])([^!@#$%^&*()'"\\]{16,64})\1|([^!@#$%^&*()'"\\\s]{16,64}))'''),
         "ALIYUN_OSS_ACCESS_KEY_SECRET"),

        (re.compile(
            r'''(?i)["']?ALIYUN_OSS_ENDPOINT["']?\s*[:=]\s*(?:(["'])([^!@#$%^&*()'"\\]{15,100})\1|([^!@#$%^&*()'"\\\s]{15,100}))'''),
         "ALIYUN_OSS_ENDPOINT"),

        (re.compile(
            r'''(?i)["']?ALIYUN_OSS_BUCKET["']?\s*[:=]\s*(?:(["'])([^'"\\]{15,100})\1|([^"'\s]{15,100}))'''),
         "ALIYUN_OSS_BUCKET"),

        (re.compile(
            r'''(?i)["']?ALIYUN_OSS_URL["']?\s*[:=]\s*(?:(["'])([^'"\\]{15,100})\1|([^"'\s]{15,100}))'''),
         "ALIYUN_OSS_URL"),

        (re.compile(
            r'''(?i)["']?ALIYUN_SMS_ACCESS_KEY_ID["']?\s*[:=]\s*(?:(["'])([^!@#$%^&*()'"\\]{12,25})\1|([^!@#$%^&*()'"\\\s]{12,25}))'''),
         "ALIYUN_SMS_ACCESS_KEY_ID"),

        (re.compile(
            r'''(?i)["']?ALIYUN_SMS_ACCESS_KEY_SECRET["']?\s*[:=]\s*(?:(["'])([^!@#$%^&*()'"\\]{12,64})\1|([^!@#$%^&*()'"\\\s]{12,64}))'''),
         "ALIYUN_SMS_ACCESS_KEY_SECRET"),

        (re.compile(
            r'''(?i)["']?WECHAT_PAYMENT_APPID["']?\s*[:=]\s*(?:(["'])([^!@#$%^&*()'"\\]{10,25})\1|([^!@#$%^&*()'"\\\s]{10,25}))'''),
         "WECHAT_PAYMENT_APPID"),

        (re.compile(
            r'''(?i)["']?QCLOUD_APP_KEY["']?\s*[:=]\s*(?:(["'])([^!@#$%^&*()'"\\]{25,48})\1|([^!@#$%^&*()'"\\\s]{25,48}))'''),
         "QCLOUD_APP_KEY"),

        (re.compile(
            r'''(?i)["']?WECHAT_PAYMENT_MCH_ID["']?\s*[:=]\s*(?:(["'])([^!@#$%^&*()'"\\]{8,20})\1|([^!@#$%^&*()'"\\\s]{8,20}))'''),
         "WECHAT_PAYMENT_MCH_ID"),

        (re.compile(
            r'''(?i)["']?WECHAT_PAYMENT_NOTIFY_URL["']?\s*[:=]\s*(?:(["'])([^!@#$%^&*()'"\\]{10,100})\1|([^!@#$%^&*()'"\\\s]{10,100}))'''),
         "WECHAT_PAYMENT_NOTIFY_URL"),

        (re.compile(
            r'''(?i)["']?WECHAT_PAYMENT_KEY["']?\s*[:=]\s*(?:(["'])([^!@#$%^&*()'"\\]{12,48})\1|([^!@#$%^&*()'"\\\s]{12,48}))'''),
         "WECHAT_PAYMENT_KEY"),

        (re.compile(
            r'''(?i)["']?IM_SDK_APPID["']?\s*[:=]\s*(?:(["'])([^!@#$%^&*()'"\\]{8,20})\1|([^!@#$%^&*()'"\\\s]{8,20}))'''),
         "IM_SDK_APPID"),

        (re.compile(
            r'''(?i)["']?IM_SDK_KEY["']?\s*[:=]\s*(?:(["'])([^!@#$%^&*()'"\\]{25,80})\1|([^!@#$%^&*()'"\\\s]{25,80}))'''),
         "IM_SDK_KEY"),

        (re.compile(
            r'''(?i)["']?IM_SDK_IDENTIFIER["']?\s*[:=]\s*(?:(["'])([^!@#$%^&*()'"\\]{5,16})\1|([^!@#$%^&*()'"\\\s]{5,16}))'''),
         "IM_SDK_IDENTIFIER"),

        (re.compile(
            r'''(?i)["']?AIP_APP_ID["']?\s*[:=]\s*(?:(["'])([^!@#$%^&*()'"\\]{5,32})\1|([^!@#$%^&*()'"\\\s]{5,32}))'''),
         "AIP_APP_ID"),

        (re.compile(
            r'''(?i)["']?AIP_API_KEY["']?\s*[:=]\s*(?:(["'])([^!@#$%^&*()'"\\]{12,32})\1|([^!@#$%^&*()'"\\\s]{12,32}))'''),
         "AIP_API_KEY"),

        (re.compile(
            r'''(?i)["']?AIP_SECRET_KEY["']?\s*[:=]\s*(?:(["'])([^!@#$%^&*()'"\\]{12,64})\1|([^!@#$%^&*()'"\\\s]{12,64}))'''),
         "AIP_SECRET_KEY"),

        (re.compile(
            r'''(?i)["']?ALIPAY_APP_ID["']?\s*[:=]\s*(?:(["'])([^!@#$%^&*()'"\\]{12,32})\1|([^!@#$%^&*()'"\\\s]{12,32}))'''),
         "ALIPAY_APP_ID"),

        (re.compile(
            r'''(?i)["']?ALIPAY_PRIVATE_KEY["']?\s*[:=]\s*(?:(["'])([^!@#$%^&*()'"\\]{150,200})\1|([^!@#$%^&*()'"\\\s]{150,200}))'''),
         "ALIPAY_PRIVATE_KEY"),

        (re.compile(
            r'''(?i)["']?ALIPAY_PUBLIC_KEY["']?\s*[:=]\s*(?:(["'])([^!@#$%^&*()'"\\]{150,200})\1|([^!@#$%^&*()'"\\\s]{150,200}))'''),
         "ALIPAY_PUBLIC_KEY"),

        (re.compile(
            r'''(?i)["']?ALIPAY_NOTIFY_URL["']?\s*[:=]\s*(?:(["'])([^!@#$%^&*()'"\\]{10,100})\1|([^!@#$%^&*()'"\\\s]{10,100}))'''),
         "ALIPAY_NOTIFY_URL"),

        (re.compile(
            r'''(?i)["']?QiNiuYun_Access_Key["']?\s*[:=]\s*(?:(["'])([^!@#$%^&*()'"\\]{25,64})\1|([^!@#$%^&*()'"\\\s]{25,64}))'''),
         "QiNiuYun_Access_Key"),

        (re.compile(
            r'''(?i)["']?QiNiuYun_Secret_Key["']?\s*[:=]\s*(?:(["'])([^!@#$%^&*()'"\\]{25,64})\1|([^!@#$%^&*()'"\\\s]{25,64}))'''),
         "QiNiuYun_Secret_Key"),

        (re.compile(
            r'''(?i)["']?QiNiuYun_Bucket["']?\s*[:=]\s*(?:(["'])([^!@#$%^&*()'"\\]{10,100})\1|([^!@#$%^&*()'"\\\s]{10,100}))'''),
         "QiNiuYun_Bucket"),

        (re.compile(
            r'''(?i)["']?ding_appId["']?\s*[:=]\s*(?:(["'])([^!@#$%^&*()'"\\]{12,32})\1|([^!@#$%^&*()'"\\\s]{12,32}))'''),
         "ding_appId"),

        (re.compile(
            r'''(?i)["']?ding_appSecret["']?\s*[:=]\s*(?:(["'])([^!@#$%^&*()'"\\]{12,32})\1|([^!@#$%^&*()'"\\\s]{20,64}))'''),
         "ding_appSecret"),

        (re.compile(r'\bAKID[A-Za-z\d]{13,40}\b'), "腾讯云 AccessKey ID"),  # 未验证
        (re.compile(r'AKID[A-Za-z0-9]{13,20}'), "腾讯云  AccessKey ID"),  # 未验证
        (re.compile(r'\bJDC_[0-9A-Z]{25,40}\b'), "京东云 AccessKey ID"),  # 未验证
        # (re.compile(r'"''[A-Z0-9]{16}["'']'), "亚马逊 AccessKey ID"),  # 未验证
        (re.compile(r'\b(?:AKLT|AKTP)[a-zA-Z0-9]{35,50}\b'), "火山引擎 AccessKey ID"),  # 未验证
        (re.compile(r'\bAKLT[a-zA-Z0-9\-_]{16,28}\b'), "金山云 AccessKey ID"),  # 未验证
        (re.compile(r'\bAIza[0-9A-Za-z_\-]{35}\b'), "谷歌云 AccessKey ID"),  # 未验证
        (re.compile(r'\bGOOG[\w\W]{10,30}\b'), "Google AccessKeyID"),  # 未验证
        (re.compile(r'\bAZ[A-Za-z0-9]{34,40}\b'), "Microsoft Azure AccessKeyID"),  # 未验证
        (re.compile(r'\bIBM[A-Za-z0-9]{10,40}\b'), "IBM Cloud AccessKeyID"),  # 未验证
        (re.compile(r'\b[A-Z0-9]{20}\b'), "华为云 AccessKeyID"),  # 未验证
        (re.compile(r'''["']AK[A-Za-z0-9]{10,40}["']'''), "百度云 AccessKeyID"),  # 未验证
        (re.compile(r'\bAKLT[a-zA-Z0-9-_]{0,252}\b'), "火山引擎 AccessKeyID"),  # 未验证
        (re.compile(r'\bJDC_[A-Z0-9]{28,32}\b'), "京东云 AccessKeyID"),  # 未验证
        (re.compile(r'\bUC[A-Za-z0-9]{10,40}\b'), "UCloud AccessKeyID"),  # 未验证
        (re.compile(r'''["']QY[A-Za-z0-9]{10,40}["']'''), "青云 AccessKeyID"),  # 未验证
        (re.compile(r'\bAKLT[a-zA-Z0-9-_]{16,28}\b'), "金山云 AccessKeyID"),  # 未验证
        (re.compile(r'\bCTC[A-Za-z0-9]{10,60}\b'), "天翼云 AccessKeyID"),  # 未验证
        (re.compile(r'\bLTC[A-Za-z0-9]{10,60}\b'), "联通云 AccessKeyID"),  # 未验证
        (re.compile(r'''["']YD[A-Za-z0-9]{10,60}["']'''), "移动云 AccessKeyID"),  # 未验证
        (re.compile(r'\bLTAI[A-Za-z\d]{12,30}\b'), "阿里云 AccessKeyID"),
        (re.compile(r'\b(?!(?:.*[\/.]))(?=(?:.*\d){2})[A-Za-z\d]{30}\b'), "阿里云 AccessKeySecret"),

        (re.compile(r'''(?i)^["']?(?=(?:[0-9a-f]*[a-f]){5})(?=(?:[0-9a-f]*[0-9]){5})[0-9a-f]{32}["']?$'''), "MD5"),

        (re.compile(r'''[=:]?\s*["\']?(wx[a-z0-9]{15,18})["\']?'''), "微信 公众号/小程序 APPID"),

        (re.compile(r'\bhttps://oapi.dingtalk.com/robot/send\?access_token=[a-z0-9]{50,80}\b'), "钉钉 webhook"),
        # 未验证

        # (re.compile(r'''[=:]?\s*["']?(ding[a-z0-9]{18})["']?'''), "ding_appId"),
        (re.compile(r'''\bding[a-z0-9]{16,18}\b'''), "ding_appId corpId"),

        (re.compile(
            r'''[=:]?\s*["']((?=(?:[^A-Z]*[A-Z]){24})(?=(?:[^a-z]*[a-z]){24})(?=(?:[^0-9]*[0-9]){10})[A-Za-z0-9_]{64})["']'''),
         "ding_appSecret"),  # 25个大写，25个小写，13个数字，1个下划线,总长64

        # (re.compile(r'''[=:]?\s*["']((?=(?:[^A-Z]*[A-Z]){12})(?=(?:[^a-z]*[a-z]){12})(?=(?:[^0-9]*[0-9]){8})[A-Za-z0-9-]{40})["']'''),"QiNiuYun_Key"),  # 13个大写，16个小写，19个数字，2个-,总长40

        # 其它...
        (re.compile(r'[a-zA-Z0-9_-]*:[a-zA-Z0-9_\\-]+@github\\.com*'), "Github令牌"),  # 未验证
        (re.compile(
            r'eyJ[A-Za-z0-9_/\+\-]{10,}={0,2}\.[A-Za-z0-9_/\+\-\\]{15,}={0,2}\.[A-Za-z0-9_/\+\-\\]{10,}={0,2}'),
         "JWT令牌"),  # 未验证
        (re.compile(r'\b[Bb]earer\s+[a-zA-Z0-9\-=._+/\\]{20,500}\b'), "Bearer Token"),  # 未验证
        (re.compile(r'\b[Bb]asic\s+[A-Za-z0-9+/]{18,}={0,2}\b'), "Basic Token"),  # 未验证
        (re.compile(
            r'["\'\[]*[Aa]uthorization["\'\]]*\s*[:=]\s*[\'"]?\b(?:[Tt]oken\s+)?[a-zA-Z0-9\-_+/]{20,500}[\'"]?'),
         "Auth Token"),  # 未验证
        (re.compile(
            r'-----\s*?BEGIN[ A-Z0-9_-]*?PRIVATE KEY\s*?-----[a-zA-Z0-9\/\n\r=+]*-----\s*?END[ A-Z0-9_-]*? PRIVATE KEY\s*?-----'),
         "PRIVATE KEY"),  # 未验证
        (re.compile(r'\b(glpat-[a-zA-Z0-9\-=_]{20,22})\b'), "Gitlab V2 Token"),  # 未验证
        (re.compile(r'\b((?:ghp|gho|ghu|ghs|ghr|github_pat)_[a-zA-Z0-9_]{36,255})\b'), "Github Token"),  # 未验证
        (re.compile(r'["''](ww[a-z0-9]{15,18})["'']'), "企业微信 corpid"),  # 未验证
        (re.compile(r'["''](gh_[a-z0-9]{11,13})["'']'), "微信公众号id"),
        (re.compile(r'\bhttps://qyapi.weixin.qq.com/cgi-bin/webhook/send\?key=[a-zA-Z0-9\-]{25,50}\b'),
         "企业微信 webhook"),  # 未验证
        (re.compile(r'\bhttps://oapi.dingtalk.com/robot/send\?access_token=[a-z0-9]{50,80}\b'), "钉钉 webhook"),
        # 未验证
        (re.compile(r'\bhttps://open.feishu.cn/open-apis/bot/v2/hook/[a-z0-9\-]{25,50}\b'), "飞书 webhook"),  # 未验证
        (re.compile(
            r'\bhttps://hooks.slack.com/services/[a-zA-Z0-9\-_]{6,12}/[a-zA-Z0-9\-_]{6,12}/[a-zA-Z0-9\-_]{15,24}\b'),
         "Slack webhook"),  # 未验证
        (re.compile(r'\beyJrIjoi[a-zA-Z0-9\-_+/]{50,100}={0,2}\b'), "Grafana API key"),  # 未验证
        (re.compile(r'\bglc_[A-Za-z0-9\-_+/]{32,200}={0,2}\b'), "Grafana cloud API token"),  # 未验证
        (re.compile(r'\b1[34578]\d{9}\b'), "手机号"),

        (re.compile(r'[a-zA-Z0-9_.]+@[a-zA-Z0-9]+\.(?:com|cn|net|org|edu|gov|co\.uk|info|biz|io|jp|de|us|ac\.cn)'),
         "邮箱"),

        # (re.compile(r'[a-z0-9_.]+@[a-zA-Z0-9]+\.(?!png|jpg|gif)[a-zA-Z0-9.]+'), "邮箱"),
        (re.compile(r'\d{6}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx]'), "身份证号码"),

        # 自定义敏感信息
        # (re.compile(r'''(?i)["']?password["']?\s*[:=]\s*(?:(["'])([a-zA-Z0-9!@#$%^&*()_-]+)\1|([a-zA-Z0-9!@#$%^&*()_-]{3,10}))'''), "password"),
        # (re.compile(r'''(?i)["']?pass["']?\s*[:=]\s*(?:(["'])([a-zA-Z0-9]+)\1|([a-zA-Z0-9]{3,10}))'''), "pass"),
        # (re.compile(r'''(?i)["']?username["']?\s*[:=]\s*(?:(["'])([a-zA-Z0-9]+)\1|([a-zA-Z0-9]{3,10}))'''), "username"),
        # (re.compile(r'''(?i)["']?user["']?\s*[:=]\s*(?:(["'])([a-zA-Z0-9]+)\1|([a-zA-Z0-9]{3,10}))'''), "user"),

        (re.compile(r'''(?i)["']?secret["']?\s*[:=]\s*(?:(["'])([^'"\\]{4,50})\1|([^"'\\\s]{4,50}))'''), "secret"),

        (re.compile(r'''(?i)["']?osskey["']?\s*[:=]\s*(?:(["'])([^'"\\]{12,64})\1|([^"'\s]{4,64}))'''), "osskey"),

        (re.compile(
            r'''(?i)["']?appid["']?\s*[:=]\s*(?:(["'])([^!@#$%^&*()'".\\]{4,50})\1|([^!@#$%^&*()'".\\\s]{4,32}))'''),
         "appid"),

        (re.compile(
            r'''(?i)["']?app_id["']?\s*[:=]\s*(?:(["'])([^!@#$%^&*()'".:,\\]{4,50})\1|([^!@#$%^&*()'".\\\s]{4,32}))'''),
         "app_id"),

        (re.compile(
            r'''(?i)["']?appsecret["']?\s*[:=]\s*(?:(["'])([^!@#$%^&*()'"\\]{10,64})\1|([^!@#$%^&*()'"\\\s]{10,64}))'''),
         "appsecret"),

        (re.compile(
            r'''(?i)["']?appKeySecret["']?\s*[:=]\s*(?:(["'])([^!@#$%^&*()'"\\]{10,64})\1|([^!@#$%^&*()'"\\\s]{10,64}))'''),
         "appKeySecret"),

        (re.compile(
            r'''(?i)["']?corpid["']?\s*[:=]\s*(?:(["'])([^!@#$%^&*()'"._\\]{8,64})\1|([^!@#$%^&*()'"._\\\s]{8,64}))'''),
         "corpid"),

        (re.compile(
            r'''(?i)["']?corpsecret["']?\s*[:=]\s*(?:(["'])([^!@#$%^&*()'"\\]{8,64})\1|([^!@#$%^&*()'"\\\s]{8,64}))'''),
         "corpsecret"),

        (re.compile(
            r'''(?i)["']?app_secret["']?\s*[:=]\s*(?:(["'])([^!@#$%^&*()'"\\]{8,64})\1|([^!@#$%^&*()'"\\\s]{8,64}))'''),
         "app_secret"),

        (re.compile(r'''(?i)["']?T_access_token["']?\s*[:=]\s*(?:(["'])(.*?)\1|([^"'\s]+))'''), "T_access_token"),
        (re.compile(r'''(?i)["']?accessKeySecret["']?\s*[:=]\s*(?:(["'])(.*?)\1|([^"'\s]+))'''), "accessKeySecret"),
        (re.compile(r'''(?i)["']?accessKeyId["']?\s*[:=]\s*(?:(["'])(.*?)\1|([^"'\s]+))'''), "accessKeyId"),
        (re.compile(r'''(?i)["']?aliosstoken["']?\s*[:=]\s*(?:(["'])(.*?)\1|([^"'\s]+))'''), "aliosstoken"),
        (re.compile(r'''(?i)["']?dingtalkunionid["']?\s*[:=]\s*(?:(["'])(.*?)\1|([^"'\s]+))'''), "dingtalkunionid"),

        # SecretFinder 源项目正则 未验证
        # (re.compile(r'AIza[0-9A-Za-z-_]{35}'), "google_api"),
        # (re.compile(r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}'), "firebase"),
        # (re.compile(r'6L[0-9A-Za-z-_]{38}|^6[0-9a-zA-Z_-]{39}$'), "google_captcha"),
        # (re.compile(r'ya29\.[0-9A-Za-z\-_]+'), "google_oauth"),
        (re.compile(r'A[SK]IA[0-9A-Z]{16}'), "amazon_aws_access_key_id"),
        # (re.compile(r'amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'),
        # "amazon_mws_auth_token"),
        # (re.compile(r's3\.amazonaws.com[/]+|[a-zA-Z0-9_-]*\.s3\.amazonaws.com'), "amazon_aws_url"),
        # (re.compile(
        # r"([a-zA-Z0-9-\._]+\.s3\.amazonaws\.com|s3://[a-zA-Z0-9-\._]+|s3-[a-zA-Z0-9-\._\/]+|s3.amazonaws.com/[a-zA-Z0-9-\._]+|s3.console.aws.amazon.com/s3/buckets/[a-zA-Z0-9-\._]+)"),
        # "amazon_aws_url2"),
        # (re.compile(r'EAACEdEose0cBA[0-9A-Za-z]+'), "facebook_access_token"),
        # (re.compile(r'basic [a-zA-Z0-9=:_\+\/-]{5,100}'), "authorization_basic"),
        # (re.compile(r'bearer [a-zA-Z0-9_\-\.=:_\+\/]{5,100}'), "authorization_bearer"),
        # (re.compile(r'SK[0-9a-fA-F]{32}'), "twilio_api_key"),
        # (re.compile(r'AC[a-zA-Z0-9_\-]{32}'), "twilio_account_sid"),
        # (re.compile(r'AP[a-zA-Z0-9_\-]{32}'), "twilio_app_sid"),
        # (re.compile(r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}'), "paypal_braintree_access_token"),
        # (re.compile(r'sq0csp-[0-9A-Za-z\-_]{43}|sq0[a-z]{3}-[0-9A-Za-z\-_]{22,43}'), "square_oauth_secret"),
        # (re.compile(r'sqOatp-[0-9A-Za-z\-_]{22}|EAAA[a-zA-Z0-9]{60}'), "square_access_token"),
        # (re.compile(r'sk_live_[0-9a-zA-Z]{24}'), "stripe_standard_api"),
        # (re.compile(r'rk_live_[0-9a-zA-Z]{24}'), "stripe_restricted_api"),
        (re.compile(r'-----BEGIN RSA PRIVATE KEY-----'), "rsa_private_key"),
        (re.compile(r'-----BEGIN DSA PRIVATE KEY-----'), "ssh_dsa_private_key"),
        (re.compile(r'-----BEGIN EC PRIVATE KEY-----'), "ssh_dc_private_key",),
        (re.compile(r'-----BEGIN PGP PRIVATE KEY BLOCK-----'), "pgp_private_block"),
        (re.compile(r'ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*$'), "json_web_token"),
        # (re.compile(r'"api_token":"(xox[a-zA-Z]-[a-zA-Z0-9-]+)"'), "slack_token"),
        (re.compile(r'[-]+BEGIN [^\s]+ PRIVATE KEY[-]+[\s]*[^-]*[-]+END [^\s]+ PRIVATE KEY[-]+'), "SSH_privKey"),

    ]

    return pattern_description
