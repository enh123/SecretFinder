import re
from typing import List, Tuple
from colorama import Fore
from modules import config

# 你指定的最优正则
PARAM_PATTERN = re.compile(r'[?&]([a-zA-Z0-9_\-.]+)=([^&#\s]*)')


def _is_valid_param(param: str, max_len: int) -> bool:
    param = param.strip()
    if not param or len(param) > max_len or param.isdigit():
        return False
    unique_digits_count = len({char for char in param if char.isdigit()})
    if unique_digits_count >= 3:
        return False
    if len(param) == 8 and unique_digits_count >= 2:
        return False
    return True


def main() -> Tuple[List[str], List[str]]:
    # 改为列表，不去重，保留所有匹配结果
    key_list = []
    value_list = []

    url_list = config.get_url_list()
    if not url_list:
        return [], []

    for url in url_list:
        url = url.strip()
        if not url:
            continue

        # 提取参数
        for key, value in PARAM_PATTERN.findall(url):
            # 校验通过直接追加，不去重
            if _is_valid_param(key, 25):
                key_list.append(key)
            if _is_valid_param(value, 30):
                value_list.append(value)

    return key_list, value_list