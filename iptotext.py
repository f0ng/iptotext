# _*_ coding:utf-8 _*_
__author__ = 'f0ng'

from burp import IBurpExtender
from burp import IHttpListener
from burp import IHttpRequestResponse
from burp import IResponseInfo
from burp import IRequestInfo
from burp import IHttpService
import sys
import time
import os
import re
import requests
from hashlib import md5
import random

a_set = set()

def randmd5():
    new_md5 = md5()
    new_md5.update(str(random.randint(1, 1000)))
    return new_md5.hexdigest()[:6]


class BurpExtender(IBurpExtender, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        print("[+] #####################################")
        print("[+]     iptotext")
        print("[+]     Author:   f0ng")
        print("[+] #####################################\r\n\r\n")
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName('iptotext')
        callbacks.registerHttpListener(self)

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        response_is_json = False
        # if toolFlag == self._callbacks.TOOL_PROXY or toolFlag == self._callbacks.TOOL_REPEATER:
        if toolFlag == self._callbacks.TOOL_PROXY or toolFlag == self._callbacks.TOOL_REPEATER:
            # 监听Response
            if not messageIsRequest:
                

                '''请求数据'''
                # 获取请求包的数据
                resquest = messageInfo.getRequest()
                analyzedRequest = self._helpers.analyzeRequest(resquest)
                request_header = analyzedRequest.getHeaders()
                request_bodys = resquest[analyzedRequest.getBodyOffset():].tostring()
                request_host, request_Path = self.get_request_host(request_header)
                request_contentType = analyzedRequest.getContentType()
                #print "request_contentType:"+str(request_contentType)

                '''响应数据'''
                # 获取响应包数据
                response = messageInfo.getResponse()
                analyzedResponse = self._helpers.analyzeResponse(response)  # returns IResponseInfo
                response_headers = analyzedResponse.getHeaders()
                response_bodys = response[analyzedResponse.getBodyOffset():].tostring()

                # 获取服务信息
                httpService = messageInfo.getHttpService()
                port = httpService.getPort()
                host = httpService.getHost()

                content = str(response_headers) + str(response_bodys)

                assets = stringIsAssets(content)


                host_lists = host.split(".")

                if assets != False:

                    if is_number(host_lists[-1]):
                        filename = str(host) + ".txt"

                    else:
                        filename = host_lists[-3] + "." + host_lists[-2] + "." + host_lists[-1] + ".txt"

                    with open("/Users/f0ngf0ng/BURP/BurpUnlimited/ip/" + filename,"w+") as file:
                        ip_lists = assets.split(",")

                        for file_single in file:
                            a_set.add(file_single.strip())


                        for ip_split in ip_lists:
                            if assets != False:

                                if ip_split not in a_set:
                                    file.writelines(ip_split + '\n')    

                                            

    # 获取请求的url
    def get_request_host(self, reqHeaders):
        uri = reqHeaders[0].split(' ')[1]
        host = reqHeaders[1].split(' ')[1]
        return host, uri

def stringIsAssets(string):
        assets = re.findall(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b', string)
        if assets != []:
            assetss = set(assets)
            assetsSet = set()
            for i in assets:
                assetsSet.add(i)
            assetss = ','.join(assetsSet)
            return assetss
        return False

def is_number(s):
    try:
        float(s)
        return True
    except ValueError:
        pass

    try:
        import unicodedata
        unicodedata.numeric(s)
        return True
    except (TypeError, ValueError):
        pass

    return False