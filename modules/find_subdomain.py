import re
from modules import config
import tldextract

def find_subdomain(response_text):
    url = config.get_value("url")
    domain = config.get_value("domain")
    type = None
    domains = None
    if domain:
        if ',' in domain:
            type="multi_domain"
            domains = domain.split(',')
        else:
            type="single_domain"
    elif not domain and not config.get_value("url_list") and url:
        type="single_domain"
        ext = tldextract.extract(url)
        domain = f"{ext.domain}.{ext.suffix}"
    else:
        return

    if type == "single_domain":
        regex = r'(?:[a-zA-Z0-9_-]+\.)+' + domain
        try:
            subdomains = re.findall(regex, response_text, re.IGNORECASE)
            if subdomains:
                for subdomain in subdomains:
                    config.set_subdomain(subdomain.strip())
        except:
            pass
    if type=="multi_domain":
        for domain in domains:
            regex = r'(?:[a-zA-Z0-9_-]+\.)+' + domain
            try:
                subdomains = re.findall(regex, response_text, re.IGNORECASE)
                if subdomains:
                    for subdomain in subdomains:
                        config.set_subdomain(subdomain.strip())
            except:
                pass








