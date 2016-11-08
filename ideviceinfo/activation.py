#!/usr/bin/python

import requests
import base64
import urllib

headers = {'User Agent': 'iTunes/12.5.1 (Windows; Microsoft Windows 7 x64 Business Edition Service Pack 1 (Build 7601); x64) AppleWebKit/7602.1050.4.4',
	'Accept' : 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'}

with open('data/activation-info.xml', 'rb') as myfile:
	data=myfile.read()

data = { "activation-info-base64" : base64.b64encode(bytes(data)) }
postdata = urllib.urlencode(data)
print(postdata)
#r = requests.post("https://albert.apple.com/deviceservices/deviceActivation", data=postdata, headers=headers)
#print("Received response")
#print(r.text)
