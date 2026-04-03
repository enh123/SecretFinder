import re
from functools import lru_cache

import tldextract

from modules import config


@lru_cache(maxsize=1)  # Least Recently Used Cache
def _get_patterns():
    url = config.get_args("url")
    url_list = config.get_url_list()
    domain_list = config.get_args("domain_list")

    patterns = []
    if domain_list:
        for dom in domain_list:
            patterns.append(
                re.compile(r'(?:[A-Za-z0-9_-]+\.)+' + re.escape(dom))
            )
    elif url and not url_list:
        parsed = tldextract.extract(url)
        top = f"{parsed.domain}.{parsed.suffix}"
        patterns.append(
            re.compile(r'(?:[A-Za-z0-9_-]+\.)+' + re.escape(top))
        )

    return patterns


def find(response_text):
    if not config.get_args("domain_list") and not config.get_args("url"):
        return

    for pat in _get_patterns():
        try:
            for sub in pat.findall(response_text):
                config.set_subdomain(sub.strip())
        except Exception:
            # 某些边缘正则可能会抛错，忽略即可
            continue
    return
