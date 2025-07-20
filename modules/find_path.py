import re

from modules import config

# hae 正则
# pattern = r'''(?:"|')(((?:[a-zA-Z]{1,10}://|//)[^"'/]{1,}\.[a-zA-Z]{2,}[^"']{0,})|((?:/|\.\./|\./)[^"'><,;|*()(%%$^/\\\[\]][^"'><,;|()]{1,})|([a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]{1,}\.(?:[a-zA-Z]{1,4}|action)(?:[\?|#][^"|']{0,}|))|([a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]{3,}(?:[\?|#][^"|']{0,}|))|([a-zA-Z0-9_\-]{1,}\.(?:\w)(?:[\?|#][^"|']{0,}|)))(?:"|')'''

#经过修改的 linkfinder 正则
pattern = r"""

  (?:"|')                               # Start newline delimiter

  (
    ((?:[a-zA-Z]{1,10}://|//)           # Match a scheme [a-Z]*1-10 or //
    [^"'/]{1,}\.                        # Match a domainname (any character + dot)
    [a-zA-Z]{2,}[^"']{0,})              # The domainextension and/or path

    |

    ((?:/|\.\./|\./|\#)                    # Start with /,../,./,#
    [^"'><,;| *()(%%$^\\\[\]]          # Next character can't be...
    [^"'><,;|()]{1,})                   # Rest of the characters can't be

    |

    ([a-zA-Z0-9_\-/]{1,}/               # Relative endpoint with /
    [a-zA-Z0-9_\-/.]{1,}                # Resource name
    \.(?:[a-zA-Z]{1,4}|action)          # Rest + extension (length 1-4 or action)
    (?:[\?|#][^"|']{0,}|))              # ? or # mark with parameters

    |

    ([a-zA-Z0-9_\-/]{1,}/               # REST API (no extension) with /
    [a-zA-Z0-9_\-/]{3,}                 # Proper REST endpoints usually have 3+ chars
    (?:[\?|#][^"|']{0,}|))              # ? or # mark with parameters

    |

    ([a-zA-Z0-9_\-]{1,}                 # filename
    \.(?:php|asp|aspx|jsp|json|
         action|html|js|txt|xml)        # . + extension
    (?:[\?|#][^"|']{0,}|))              # ? or # mark with parameters

  )

  (?:"|')                               # End newline delimiter

"""

pattern = re.compile(pattern, re.VERBOSE)


def find(response_text):
    matches = pattern.findall(response_text)

    black_list = [
        '.css', '.jpg', '.png', '.woff', '.swf'
                                         '.bmp', '.gif', '.ico', '.jpeg', '.tiff', '.webp',
        '.eot', '.otf', '.ttf', 'woff2',
        '.mp3', '.mp4', '.avi', '.mov', '.wav', '.vue', 'text/javascript', 'text/css','application/json','text/json'
    ]

    for match in matches:
        path = match[0]
        if ("http://" not in path and "https://" not in path) and not any(
                i in match[0].lower() for i in black_list):

            # if "./" in path:
            #    path = path.replace("./", '\n'+'/')
            for i in range(1, 6):
                if path:
                    if path.startswith('/'):
                        path = path[1:]
                    # elif path.startswith("#"):
                    #    path = path[1:]
                    elif path.startswith('.'):
                        path = path[1:]
            config.set_path(path.strip())
    return
