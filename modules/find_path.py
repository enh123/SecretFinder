import re
from . import config

def find_path(response_text):
    # hae 正则
    pattern = r'''(?:"|')(((?:[a-zA-Z]{1,10}://|//)[^"'/]{1,}\.[a-zA-Z]{2,}[^"']{0,})|((?:/|\.\./|\./)[^"'><,;|*()(%%$^/\\\[\]][^"'><,;|()]{1,})|([a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]{1,}\.(?:[a-zA-Z]{1,4}|action)(?:[\?|#][^"|']{0,}|))|([a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]{3,}(?:[\?|#][^"|']{0,}|))|([a-zA-Z0-9_\-]{1,}\.(?:\w)(?:[\?|#][^"|']{0,}|)))(?:"|')'''

    pattern = re.compile(pattern, re.VERBOSE)

    matches = pattern.findall(response_text)

    black_list = [
        '.css', '.jpg', '.png', '.woff','.swf'
        '.bmp', '.gif', '.ico', '.jpeg', '.tiff', '.webp',
        '.eot', '.otf', '.ttf', '.woff2',
        '.mp3', '.mp4', '.avi', '.mov', '.wav',
    ]

    for match in matches:
        path=match[0]
        if ("http://" not in path and "https://" not in path) and not any(
                i in match[0].lower() for i in black_list):
            #if "./" in path:
            #    path = path.replace("./", '\n'+'/')
            for i in range(1,5):
                if path:
                    if path.startswith('/'):
                        path = path[1:]
                    elif path.startswith('.'):
                        path = path[1:]

            config.set_path(path.strip())
