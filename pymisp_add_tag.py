#!/usr/bin/env python3
#-*- coding utf-8-*-

from pymisp import PyMISP, MISPEvent
from keys import misp_url, misp_key, misp_verifycert
import json
import urllib3

def init(url, key):
        return PyMISP(url,key,misp_verifycert,'json',debug=True)

#CRONTAB ENTRY
# m h  dom mon dow   command
#MAILTO="user@org.com"
# m h  dom mon dow   command
#00 00 * * * /usr/bin/timeout -s9 9h /usr/bin/python3 /root/PyMISP/examples/pymisp_tag_update.py > /dev/null 2>&1 
  
#Default distribution level:
#your_organization = 0
#this_community = 1
#connected_communities = 2
#all_communities = 3

#Default threat level:
#high = 1
#medium = 2
#low = 3
#undefined = 4

#Default analysis level:
#initial = 0
#ongoing = 1
#completed = 2

misp = init(misp_url,misp_key)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

result = misp.search_index(org=#add org no. id)
for event in result['response']:
        me = MISPEvent()
        me.load(event)
        me.add_tag('#insert tag name here#')
        me.add_tag('')
        me.threat_level_id = #add threat level id no.
        me.analysis = # add analysis id no.
        me.distribution = # add distribution id no.
        me.publish()
        event = misp.update(me)
        print("Event tagged: %s"%event['Event']['info'])
        misp.pushEventToZMQ(event['Event']['id'])
