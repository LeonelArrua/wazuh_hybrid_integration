#!/var/ossec/framework/python/bin/python3
# Copyright (C) 2015-2022, Wazuh Inc.
# Template by Leonardo Carlos Armesto
# Created by Leonel Arrua
#syscheck.md5_after

import json
import sys
import time
import os
from socket import socket, AF_UNIX, SOCK_DGRAM

try:
    import requests
    from requests.auth import HTTPBasicAuth
except Exception as e:
    print("No module 'requests' found. Install: pip install requests")
    sys.exit(1)

# Global vars
debug_enabled = True
pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))

print(pwd)
#exit()

json_alert = {}
now = time.strftime("%a %b %d %H:%M:%S %Z %Y")
# Set paths
log_file = '{0}/logs/integrations.log'.format(pwd)
socket_addr = '{0}/queue/sockets/queue'.format(pwd)

def main(args):
    debug("# Starting")
    # Read args
    alert_file_location = args[1]
    apikey = args[2]
    url=args[3]
    #debug("# API Key")
    #debug(apikey)
    debug("# File location")
    debug(alert_file_location)
    debug("#Hook url")
    debug(url)

    # Load alert. Parse JSON object.
    with open(alert_file_location, encoding='utf-8',errors='ignore') as alert_file:
        json_alert = json.load(alert_file)
    debug("# Processing alert")
    debug(json_alert)
    #Get the md5 hash from different alert formats
    json_alert = getmd5(json_alert)
    # Request hybrid info
    msg = request_hybrid_info(json_alert,apikey,url)
    # If positive match, send event to Wazuh Manager
    if msg:
        send_event(msg, json_alert["agent"])

def getmd5(data):
   if 'syscheck' in data:
      data = syscheck_converter(data)
      debug(f"#INFO: Alert data:{data}")
      return data
   elif 'data' in data:
      data = sysmon_converter(data)
      debug(f"#INFO: Alert data:{data}")
      return data
   else:
      return(0)

def get_highest_report(json):
 #Getting the report with most detections.
 highest = json[0]
 for i in json:
    if i['av_detect'] > highest['av_detect']:
       highest = i
 if highest['av_detect'] == 0:
  for i in json:
     if i['threat_level'] > highest ['threat_level']:
        highest = i
 return highest

def sysmon_converter(data):
   if 'hashes' in data['data']['win']['eventdata']:
      hashes_str = data['data']['win']['eventdata']['hashes']
      hashes = hashes_str.split(',')
      md5_hash = None
      for hash in hashes:
        if 'MD5=' in hash:
          md5_hash = hash.split('=')[1]
          break
      if md5_hash != None:
        data['data']['md5'] = md5_hash
      else:
         return(0)
   return data

def syscheck_converter(data):
   if 'syscheck' in data:
      data['data'] = {
       'md5': data["syscheck"]["md5_after"]
      }
   return data


def debug(msg):
    if debug_enabled:
        msg = "{0}: {1}\n".format(now, msg)
    print(msg)
    f = open(log_file,"a")
    f.write(str(msg))
    f.close()

def collect(data):

  av_detect = data['av_detect']

  threat_score = data['threat_score']

  verdict = data['verdict']

  vx_family = data['vx_family']

  return av_detect,threat_score,verdict,vx_family

def find_string_in_json(json_data, search_string):
  try:
   if search_string in json_data[-1]:
    return True
   else:
    return False
  except Exception as e:
   return False

def query_api(hash, apikey, url):

  data = f'hash={hash}'
  headers = {
        'accept': 'application/json',
        'api-key': apikey,
        'Content-Type': 'application/x-www-form-urlencoded'
        }
  response = requests.post(url, data=data, headers=headers)
  """
  </IMPORTANT>
  """

  if response.status_code == 200:

      json_response = response.json()

      if find_string_in_json(json_response,"av_detect") == False:
         debug("#ERROR: hybrid response is empty: No result for this hash")
         debug(json_response)
         exit(0)

      debug("#INFO: Hybrid response")
      debug(json_response)

      return json_response
  else:
      alert_output = {}
      alert_output["hybrid"] = {}
      alert_output["integration"] = "custom-hybrid"
      json_response = response.json()
      debug("# Error: The hybrid encountered an error")
      alert_output["hybrid"]["error"] = response.status_code
      alert_output["hybrid"]["description"] = json_response
      send_event(alert_output)
      exit(0)

def request_hybrid_info(alert, apikey,url):
    alert_output = {}
    # If there is no source ip address present in the alert. Exit.
    if not "md5" in alert["data"]:
        debug("#MD5 Isn't found in data")
        return(0)

    # Request info using hybrid API
    full_data = query_api(alert["data"]["md5"], apikey, url)
    data= get_highest_report(full_data)
    # Create alert
    alert_output["hybrid"] = {}
    alert_output["integration"] = "custom-hybrid"
    alert_output["hybrid"]["found"] = 1
    alert_output["hybrid"]["source"] = {}
    alert_output["hybrid"]["source"]["alert_id"] = alert["id"]
    alert_output["hybrid"]["source"]["rule"] = alert["rule"]["id"]
    alert_output["hybrid"]["source"]["description"] = alert["rule"]["description"]
    if 'full_log' in alert:
     alert_output["hybrid"]["source"]["full_log"] = alert["full_log"]
    alert_output["hybrid"]["source"]["data"] = alert["data"]

    if alert_output["hybrid"]["found"] == 1:
        av_detect,threat_score,verdict,vx_family = collect(data)

        # Populate JSON Output object with hybrid request

        alert_output["hybrid"]["av_detect"] = av_detect

        alert_output["hybrid"]["threat_score"] = threat_score

        alert_output["hybrid"]["verdict"] = verdict

        alert_output["hybrid"]["vx_family"] = vx_family

        alert_output["hybrid"]["hybrid_full_report"] = full_data

        debug(alert_output)

    return(alert_output)

def send_event(msg, agent = None):
    if not agent or agent["id"] == "000":
        string = '1:hybrid:{0}'.format(json.dumps(msg))
    else:
        string = '1:[{0}] ({1}) {2}->hybrid:{3}'.format(agent["id"], agent["name"], agent["ip"] if "ip" in agent else "any", json.dumps(msg))

    debug(string)
    sock = socket(AF_UNIX, SOCK_DGRAM)
    sock.connect(socket_addr)
    sock.send(string.encode())
    sock.close()

if __name__ == "__main__":
    try:
        # Read arguments
        bad_arguments = False
        if len(sys.argv) >= 4:
            msg = '{0} {1} {2} {3} {4}'.format(now, sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4] if len(sys.argv) > 4 else '')
            debug_enabled = (len(sys.argv) > 4 and sys.argv[4] == 'debug')
        else:
            msg = '{0} Wrong arguments'.format(now)
            bad_arguments = True

        # Logging the call
        f = open(log_file, 'a')
        f.write(str(msg) + '\n')
        f.close()

        if bad_arguments:
            debug("# Exiting: Bad arguments.")
            sys.exit(1)

        # Main function
        main(sys.argv)

    except Exception as e:
        debug(str(e))
        raise
