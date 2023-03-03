'''
Lookup proxy based on wpad.intel.com for a given IP address and url
'''

import requests
from py_mini_racer import MiniRacer
import os
import socket
import urllib
import logging

class AutoProxy:
    JS_CODE = '''
        function myIpAddress() {{ 
            return "{my_ip}"; 
        }}

        function dnsResolve(host) {{
            return "{host_ip}";
        }}

        {pac_utils_js}

        {wpad_js}

    '''

    def __init__(self):
        with open(os.path.join(os.path.dirname(__file__), 'pac-utils.js')) as fd:
            self.pac_utils_js = fd.read()
    
    def lookup(self, url, ip):
        url = url.lower()
        if not (url.startswith("http://") or url.startswith("https://")):
            url = "https://" + url

        try:
            host = urllib.parse.urlparse(url).netloc
        except Exception as ex:
            raise Exception("Failed to parse URL: {url}")
        if not host:
            raise Exception("Failed to get host from URL: {url}")

        try:
            host_ip = socket.gethostbyname(host)
        except Exception as ex:
            raise Exception(f"Failed to resolve host: {host} - {ex}")
            
        rurl = f'http://wpad.intel.com?ip={ip}'
        print("Requesting: ", rurl)
        r = requests.get(rurl)
        try:
            r.raise_for_status()
            wpad_js = r.text
        except Exception as ex:
            raise Exception(f"Failed to fetch wpad.dat for ip {ip}: {ex}")
        
        js_code = self.JS_CODE.format(my_ip=ip, host_ip=host_ip, pac_utils_js=self.pac_utils_js, wpad_js=wpad_js)

        ctx = MiniRacer()
        try:
            ctx.eval(js_code)
        except Exception as ex:
            raise Exception(f"Failed to eval js_code: {ex}") from ex
        try:
            proxy = ctx.call("FindProxyForURL", url, host)
        except Exception as ex:
            raise Exception(f"Failed to call FindProxyForURL() - {ex}") from ex
        return host, proxy

        
if __name__ == '__main__':
    my_ips = ["10.67.198.214",]
    urls = '''
        https://github.com/rrvarra/github-test
        https://www.kollective.app/rrvarra/github-test
        https://outlook.office365.com/a/bc
        https://yahoo.com/mail
        www.google.com
    '''
    urls = filter(len, map(str.strip, urls.split('\n')))
    
    ap = AutoProxy()
    for my_ip in my_ips:
        for url in urls:
            host, proxy = ap.lookup(url, my_ip)
            print(f"{my_ip} {host} = '{proxy}'")
                