# !/usr/bin/env python
# -*- coding: UTF-8 -*-
from urllib.parse import urlparse
from pocsuite3.api import Output, POCBase, POC_CATEGORY, register_poc, requests, VUL_TYPE

class socks5(POCBase):
    vulID = 'Unauthorized SOCKS proxy'
    version = '1.0'
    author = ['Warin9_0']
    vulDate = '2022-07-01'
    createDate = '2022-07-01'
    updateDate = '2022-07-01'
    references = ['']
    name = 'Free sex socks'
    appPowerLink = ''
    appName = 'The Matrix'
    appVersion = """socks4/socks5"""
    vulType = VUL_TYPE.CODE_EXECUTION
    desc = '''The Matrix'''
    samples = ['']
    install_requires = ['']
    category = POC_CATEGORY.EXPLOITS.WEBAPP

    # 获取当前IP地址
    def get_localhost(self):
        localhost = requests.get('http://httpbin.org/ip').json()
        return localhost['origin']

    def _verify(self):
        result = {}
        host = urlparse(self.url).hostname
        port = urlparse(self.url).port
        self.timeout = 5
        # 代理部分
        socks = ['socks4', 'socks5']
        for sock in socks:
            socks_url = '{sock}://{host}:{port}'.format(sock=sock, host=host, port=port)
            proxies = {
                'http': socks_url,
                'https': socks_url
            }
            # 请求部分
            try:
                r = requests.get('http://httpbin.org/ip', proxies=proxies, timeout=self.timeout, verify=False,
                                 allow_redirects=False)
                if r.json()['origin'] != self.get_localhost():
                    result['socks'] = socks_url
                    result['successful_ip'] = r.json()['origin']
                    break
            except Exception:
                pass
        return self.parse_output(result)

    def _attack(self):
        return self._verify()

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('url is not vulnerable')
        return output

register_poc(socks5)
