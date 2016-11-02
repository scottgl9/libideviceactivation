#!/usr/bin/python

import requests

headers = {'User Agent': 'iOS Device Activator (MobileActivation-20 built on Jan 15 2012 at 19:07:28)'}

payload=open('data','rb').read()
r = requests.post("https://albert.apple.com/deviceservices/deviceActivation", data=payload, headers=headers)
