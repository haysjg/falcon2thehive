#!/usr/bin/env python3

from falconpy import EventStreams
import json
import time
import datetime
import requests
import os
import sys
import logging
import threading
import traceback
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from thehive4py.api import TheHiveApi
from thehive4py.models import Alert, AlertArtifact, CustomFieldHelper


# set offset high to only get new events.
offset = 999999999
#offset = 1

# ###################### TO BE CUSTOMIZED ##################
g_token_url = "https://api.crowdstrike.com/oauth2/token"
g_client_id = 'XXXXXXXXXXXXXX'
g_client_secret = 'YYYYYYYYYY'
appId = "falcon2thehive"
THEHIVE_URL = 'http://127.0.0.1:9000'
THEHIVE_API_KEY = 'XXXXXXXXXXXXXXX'

api = TheHiveApi(THEHIVE_URL, THEHIVE_API_KEY)
#refreshURL = "https://firehose.crowdstrike.com:443/sensors/entities/datafeed-actions/v1/0"

falcon = EventStreams(client_id=g_client_id, \
                      client_secret=g_client_secret
                      )



response = falcon.list_available_streams(app_id=appId, format="flatjson")
dump = json.dumps(response, sort_keys=True, indent=4)
#print(dump)    #DEBUG



response2use = str(response).replace("\'", "\"")
load = json.loads(response2use)

for i in load["body"]["resources"]:
    print("Data Feed URL : " + i["dataFeedURL"])
    print("Generated Token : " + i["sessionToken"]["token"])
    dataFeedURL = i["dataFeedURL"]
    generatedToken = i["sessionToken"]["token"]
    refreshURL = i["refreshActiveSessionURL"]

# Below variables are created for compatibility reasons
url = dataFeedURL
token = generatedToken

'''
def refresh_stream():
    # refresh active streams
    # @params: None
    # @returns: the access_token
    print("INFO : Refreshing Stream Token")
    print('URL used for refresh operation : %s' % refreshURL)
    refreshHeaders = {'Authorization': "bearer %s" % generatedToken, \
            'Accept': "application/json", \
            'Content-Type': "application/json"}
    print("headers : %s" % refreshHeaders)
    
    try:
        response = requests.request("POST", refreshURL, headers=refreshHeaders)
        
        print("Response : %s" % response)
        if (response.status_code == 200):
            return True
        else:
            return False

    except Exception as e:
        self.error_handler(e)
        print("Unable to refresh stream_token")
        return False

'''
def refresh_stream():
    falcon = EventStreams(client_id=g_client_id,
            client_secret=g_client_secret
            )

    PARTITION = 0   #Refresh the partition we are working with

    response = falcon.refresh_active_stream(action_name="refresh_active_stream_session",
            app_id=appId,
            partition=0
            )
    print(response)

    httpCode = response["status_code"]
    print('HTTP Code is : %s' % httpCode)

    if (httpCode == 200):
        return True
    else:
        return False
        print("Unable to refresh stream_token")



def error_handler(self, e):
    traceback.print_exc()
    print(e)



####################################
## BELOW WE LOOK FOR NEW DETECTIONS
####################################

url += "&offset=%s" % offset
        
try:
    epoch_time = int(time.time())
    headers = {'Authorization': 'Token %s' % token, 'Connection': 'Keep-Alive'}
    r = requests.get(url, headers=headers, stream=True)
    #print("Streaming API Connection established. Thread: %s" % id)
    
    
   


    for line in r.iter_lines():
        try:
            if line:
                decoded_line = line.decode('utf-8')

                print("Got a new message, decoding to JSON...")
                decoded_line = json.loads(decoded_line)
                print(decoded_line)


                #if self.was_event_handled(decoded_line):
                #    print("This is not a new event, already handled!")
                #else:
                #print("This is a new event!")
                #metadata_object = decoded_line.get('metadata', {})
                #print('type(metadata_object): %s' % type(metadata_object))
                #print('metadata_object: %s' % metadata_object)
                #isDetectionSummaryEvent = metadata_object.get('eventType')
           
                isDetectionSummaryEvent = decoded_line.get("metadata.eventType")
            
                print("isDetectionSummaryEvent: '%s'" % isDetectionSummaryEvent)
                if (isDetectionSummaryEvent == "DetectionSummaryEvent"):
                    detection_summary_event = decoded_line

                    # From there, we are ready to retreive Detection values in order to send them to The Hive
                    artifacts = []

                    ProcessStartTime = detection_summary_event.get('event.ProcessStartTime')
                    ProcessEndTime = detection_summary_event.get('event.ProcessEndTime')
                    ProcessId = detection_summary_event.get('eventProcessId')
                    ParentProcessId = detection_summary_event.get('event.ParentProcessId')
                    
                    ComputerName = detection_summary_event.get('event.ComputerName')
                    artifacts.append(AlertArtifact(dataType='hostname', data=ComputerName))

                    UserName = detection_summary_event.get('event.UserName')
                    artifacts.append(AlertArtifact(dataType='other', data="UserName = " + UserName))

                    FalconHostLink = detection_summary_event.get('event.FalconHostLink')
                    artifacts.append(AlertArtifact(dataType='other', data="Detection URL in CrowdStrike : " + FalconHostLink))

                    DetectName = detection_summary_event.get('event.DetectName')
                    
                    DetectDescription = detection_summary_event.get('event.DetectDescription')

                    Severity = detection_summary_event.get('event.Severity')
                    SeverityName = detection_summary_event.get('event.SeverityName')
                    artifacts.append(AlertArtifact(dataType='other', data="Detection Severity" + SeverityName))

                    FileName = detection_summary_event.get('event.FileName')
                    artifacts.append(AlertArtifact(dataType='filename', data=FileName))

                    FilePath = detection_summary_event.get('event.FilePath')
                    artifacts.append(AlertArtifact(dataType='other', data="FilePath : " + FilePath))

                    CommandLine = detection_summary_event.get('event.CommandLine')
                    artifacts.append(AlertArtifact(dataType='other', data="CommandLine : " + CommandLine))

                    SHA256String = detection_summary_event.get('event.SHA256String')
                    artifacts.append(AlertArtifact(dataType='hash', data=SHA256String))

                    MD5String = detection_summary_event.get('event.MD5String')
                    artifacts.append(AlertArtifact(dataType='hash', data=MD5String))

                    SHA1String = detection_summary_event.get('event.SHA1String')
                    artifacts.append(AlertArtifact(dataType='hash', data=SHA1String))

                    MachineDomain = detection_summary_event.get('event.MachineDomain')
                    artifacts.append(AlertArtifact(dataType='fqdn', data=MachineDomain))

                    SensorId = detection_summary_event.get('event.SensorId')
                    artifacts.append(AlertArtifact(dataType='other', data="Sensor ID : " + SensorId))

                    DetectId = detection_summary_event.get('event.DetectId')





                    #########################################
                    # BELOW WE PREPARE MESSAGE FOR THE HIVE
                    #########################################
                    # Prepare custom fields
                    customFields = CustomFieldHelper()\
                        .add_string('falcon-detection-url', FalconHostLink)\
                        .build()

                    # Prepare the sample Alert
                    sourceRef = DetectId
                    alert = Alert(title=DetectName,
                        tlp=3,
                        tags=['CrowdStrike', 'CS', 'Detection'],
                        description = DetectDescription,
                        type='external',
                        source='CSFalcon',
                        sourceRef=sourceRef,
                        severity=((Severity-1)), # Here we map CS Severity with TheHive's 
                        artifacts=artifacts,
                        customFields=customFields
                        )



                    # Create the alert
                    try:
                        response = api.create_alert(alert)
    
                        # DEBUG ONLY - Print the JSON response 
                        print(json.dumps(response.json(), indent=4, sort_keys=True))

                    except AlertException as e:
                        print("Alert create error: {}".format(e))


            # Refreshing stream 
            if (int(time.time()) > (900 + epoch_time)):
                print("Event Window Expired, refreshing Token")
                if (refresh_stream()):
                    print("Stream Refresh Succeded")
                    epoch_time = int(time.time())
                #else:
                    # unable to refresh token, start from scratch
                    #return
            
        except Exception as e:
            print("Error reading stream chunk")
            print("request status code %s\n%s" % (r.status_code, traceback.format_exc()))
            
            

except Exception as e:
    print("Error reading last stream chunk")
    print("request status code %s\n%s" % (r.status_code, traceback.format_exc()))
    os._exit(1)


sys.exit(0)






                    
                    
                    
                    
                    
                    
                                  


