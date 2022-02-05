# connect to matterbridge api

import logging
logger = logging.getLogger(__name__)
mp = logger.warning


import asyncio

import json
import traceback


import urllib
import urllib.request
import urllib.error


def mt_send(text="null", username="C bot", gateway="gateway1", qt=None):

    # in for all
    MT_API = "127.0.0.1:4240"
    # send msg to matterbridge
    url = "http://" + MT_API + "/api/message"

    #nc -l -p 5555 # https://mika-s.github.io/http/debugging/2019/04/08/debugging-http-requests.html
    #  url="http://127.0.0.1:5555/api/message"

#    if not username.startswith("C "):
#        username = "T " + username


    if qt:
        username = "{}\n\n{}".format("> " + "\n> ".join(qt.splitlines()),
                                       username)


#  gateway="gateway0"
    data = {
        "text": "{}".format(text),
        "username": "{}".format(username),
        "gateway": "{}".format(gateway)
    }
    #  data={"text":"test","username":"null", "gateway":"gateway0" }

    #  data=str(data)
    #  data=urlencode(data)#将字典类型的请求数据转变为url编码
    #  data=urllib.parse.quote(json.dumps(data), safe="{}:\\\"',+ ")
    #  data=urllib.parse.quote_plus(json.dumps(data))
    #  data=data.encode('ascii')#将url编码类型的请求数据转变为bytes类型
    data = json.dumps(data).encode()
    logger.debug(data)
    req_data = urllib.request.Request(
        url, data)  #将url和请求数据处理为一个Request对象，供urlopen调用
    req_data.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req_data) as res:
            #  with urllib.request.urlopen(url, data) as res:
            #    mp("send headers: "+str(res.headers))
            res = res.read().decode(
            )  #read()方法是读取返回数据内容，decode是转换返回数据的bytes格式为str
            logger.info("D: send msg to mt, res: " + res)
    except urllib.error.URLError:
        logger.warning("can not send", exc_info=True)
        pass
    except:
        logger.warning("can not send", exc_info=True)
        pass


