"""

This python script demonstrates how to detect anomaly on Security Management Appliance (SMA)

"""

import argparse
import json
import time
import requests
from  sma_credentials import *

from datetime import datetime, timedelta
from requests.auth import HTTPBasicAuth

# Disable certificate warnings (not recommended for production use)
requests.packages.urllib3.disable_warnings()

# System Parameters
port = "4431"


def get_message_tracking_data(start_date, end_date, offset: int = 0, limit: int = 20):
    """ Function for retrieving messages from the SMA """
    print("Retrieving messages from the SMA...")
    
    total_responses = limit
    full_response = []
    while total_responses == limit:

        url = f"https://{sma_hostname}:{port}/sma/api/v2.0/message-tracking/messages?" \
              f"startDate={start_date}.000Z&endDate={end_date}.000Z&ciscoHost=All_Hosts&searchOption=messages" \
              f"&offset={offset}&limit={limit}"
        try:
            # retrieving messages from the SMA
            response = requests.get(url, auth=HTTPBasicAuth(sma_username, sma_password), verify=False)
            # Check bad responses
            if response.status_code >= 200 and response.status_code < 300:

                # Number of responses 
                total_responses = response.json()["meta"]["num_bad_records"] + response.json()["meta"]["totalCount"]

                # Update the full response
                for message in response.json()["data"]:
                    full_response.append(message)
            else:
                print(json.dumps(response.json(), indent=4))
                exit()

        except Exception as err:
            print("Error fetching info from SMA: " + str(err))
        # Increment the offset
        offset += limit

    return full_response


def message_filter(message):
    if (message["attributes"]["messageStatus"] == "Delivered"):
        return True
    else:
        return False

def main(message_limit, days, status_delivered, verbose):
    # format : {"name@company.com":6}
    sender_db = {} 
    # Do we have any anomaly? 
    anomaly=False

    # Make a timestamp for a few days ago
    past = datetime.utcnow().replace(second=0, microsecond=0) - timedelta(days=days)
    # Convert into ISO Format
    start_date = past.isoformat()
    # Get the current timestamp in ISO Format
    end_date = datetime.utcnow().replace(second=0, microsecond=0).isoformat()
    # Get the last days' messages from the SMA
    message_data = get_message_tracking_data(start_date, end_date)

    print(f"Messages retrieved: {len(message_data)}")
    #print(json.dumps(message_data, indent=4))

    if verbose==True:
        print("*** FILTER ***")
        # Debugging: Print the status of each email
        for email in message_data:
            status = email["attributes"].get("messageStatus", "No Status Found")
            print(f"Email status: {status}")


    # Filter based on the Delivered Message Status
    if status_delivered: 
        # Filter the list based on "messageStatus" being "Delivered"
        filtered_message_data =  [email for email in message_data if "Delivered" in email["attributes"]["messageStatus"].values()]
        #print(filtered_message_data)      
    else:
        filtered_message_data =  message_data   
   

    print(f"Messages retrieved after messageStatus filtered : {len(filtered_message_data)}")
    
    # Iterate through all messages
    for message in filtered_message_data:
        if "attributes" in message:
            if "sender" in message["attributes"]:
                if message["attributes"]["sender"] in sender_db:
                    sender_db[message["attributes"]["sender"]]+=1
                else:
                    sender_db[message["attributes"]["sender"]]=1       

    if verbose==True:
        print(f"Full sender database:",json.dumps(sender_db, indent=4))

    print(f"Anomaly detection result:")
    if len(sender_db)>0:
        for sender, value in sender_db.items():
            # Check if the value exceeds the limit
            if value > message_limit:
                # Print the sender (key) with a value higher than the limit
                print(f"{sender}: {value}")
                anomaly=True
            

    if anomaly==False:
        print("No anomaly detected.")                        

# MAIN function 
if __name__ == "__main__":

    # Argument parser
    parser = argparse.ArgumentParser(
        description="This script shows the anomalies on SMA based on the message limit and days"
    )
    parser.add_argument("-l", help="The limit for one sender [int]",type =int, required=True)
    parser.add_argument("-d", help="The number of days to look back for messages [int]", type =int, required=True)
    parser.add_argument("-s", '--status_delivered', action='store_true',help="Filter on status=delivered",required=False)
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose mode',required=False )
    args = parser.parse_args()
    main(message_limit=args.l, days =args.d, status_delivered=args.status_delivered, verbose = args.verbose)
