# SMA_message_anomaly  

This Python script demonstrates how detect anomaly on Cisco Security Management Appliance (SMA) using message limit.  


# How to install:  

To get started, download all the files from this repository. Then, install the `requests` Python module by running:  

```bash
pip install requests
```  


Update the contents of the `sma_credentials.py` file with Your specific configuration parameters!  
  

# How to use:  

The script accepts these parameters:  
  -h, --help            show this help message and exit  
  -l L                  The limit for one sender [int]    
  -d D                  The number of days to look back for messages [int]   
  -s, --status_delivered Filter on status=delivered [optional]  
  -v, --verbose         Enable verbose mode [optional]  
 

Expected output:


To check message anomaly from the last 1 day, 10 messages per user as a limit and filter for Delivered status , use the following command:

```bash
python3 sma_anomaly.py  -d 1 -l 10 -s
Retrieving messages from the SMA...
Messages retrieved: 39
Messages retrieved after messageStatus filtered : 24
Anomaly detection result:
No anomaly detected.
```

If You change the limit to 2, You can see more "anomalies":


```bash
python3 sma_anomaly.py  -d 1 -l 2 -s 
Retrieving messages from the SMA...
Messages retrieved: 39
Messages retrieved after messageStatus filtered : 24
Anomaly detection result:
noreply@xft.com: 7
pepe12@mgfgf.com: 6
ftwrew@gmail.com: 5
```


# Useful reference:  
For more information about the Message Tracking API, refer to the Cisco ESA API Guide 15.0:
https://www.cisco.com/c/en/us/td/docs/security/esa/esa15-0/api_guide/b_Secure_Email_API_Guide_15-0/b_ESA_API_Guide_chapter_010.html#id_91367


