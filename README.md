# IP_URL_Scanner
This script submits a list of IPs/URLs to VirusTotal and MetaDefender and summarizies the output for each IP
 _(NOTE: This script does not take any input. Each script has a short premade list that was used to test and build the script.
 The script was made for to be a baseline that you can use for your own IP/URL scanning reports. You will either need to add
 more code to work with csv reports and input them here or just replace the premade list with the IP/URL with your list.)_

**The Master Branch has three different scripts:**
1. VT_url_scan.py - submits to VirusTotal
2. meta_defender_url.py - submit to MetaDefender
3. URL_Scan.py - submits to both VirusTotal and MetaDefender

The config.py is to hold API keys.

**The output:**
_(NOTE: Again sense this is a script meant to be a baseline that can be combined or used for your reports the output is
 just printed on screen. You can decide what file type you need the output written into or just copy paste the output.)_

The output for each script is similar and is printed out in json format.
They both include the raw API response for each IP/URL to review if needed.

Before the raw response is shown it shows a summary for each IP.

VirusTotal only returns one summary.
MetaDefender returns two summaries.

**How to use:**

_config.py_
This one isn't run. Just make sure to add your API keys and that they are inside quotations.


_VT_url_scan.py:_
To change the list of IP/URLs in this script you will need to replace the premade list that was used for testing on line 8.
Make sure the IP/URLs added are inside quotations. After you updated the list of IP/URLs just save the file and you can run it with
'python VT_url_scan.py' or 'python3 VT_url_scan.py' in the terminal.

_meta_defender_scan.py:_
To change the list of IP/URLs in this script you will need to replace the premade list that was used for testing on line 40.
Make sure the IP/URLs added are inside quotations. After you updated the list of IP/URLs just save the file and you can run it with
'python meta_defender_scan.py' or 'python3 meta_defender_scan.py' in the terminal.

_URL_Scan.py:_
To change the list of IP/URLs in this script you will need to replace the premade list that was used for testing on line 17.
Make sure the IP/URLs added are inside quotations. After you updated the list of IP/URLs just save the file and you can run it with
'python URL_Scan.py' or 'python3 URL_Scan.py' in the terminal.

**TroubleShooting:**
There is an error handler in the script to try making the API request again if it was unable to parse the request. In case the issue
is beyond just exceeding API request rate limits then while the script is sleeping to not over ping the API it will print the API response.
API responses can include useful information to know if something is wrong with the script or if the API had an error. 

I did not run into any errors besides exceeding API request times so I have no other tips. If I notice any trends I can add them here for reference.
