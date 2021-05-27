'''
Some definitions provided by MetaDefeender API as of 05/25/2021
Source: https://onlinehelp.opswat.com/mdcloud/2._Analyzing_IPs_with_MetaDefender_Cloud.html

The definition of the 'status' from the API response:
0 : Whitelisted: IP is listed by the source in their whitelist. Note: Not all sources provide whitelists.
1 : Blacklisted: IP is listed by the source in their blacklist. Refer to the source for more information regarding their blacklist.
3 : Failed to scan: The results could not be retrieved from our servers
5 : Unknown: The source has not listed this IP address in either their blacklist or whitelist.

#Note the assessment response can be blank, I replaces blanks with "No threat detected"
The definition of the 'assessment' from the API response:
botnet - Typically a host used to control another host or malicious process.
malware - Typically a host used to exploit and/or drop malware to a host for the first time.
phishing - A luring attempt at a victim to exfiltrate some sort of credential.
scanner - Typically infrastructure being used to scan or brute-force (SSH, RDP, telnet, etc...).
spam - Typically infrastructure being used to facilitate the sending of spam.
suspicious - There are reasons to believe this address might be conducting malicious activity
bruteforce - Such addresses have been used to conduct bruteforce password checking on login pages
tor - The address has been spotted on the "tor" network
blacklist - This address has been included in a blacklist for unspecified reasons
high risk - Highly risky address
trustworthy - Denotes that a specific entity (usually an address) should be considered harmless in nature.
'''

import requests
import json
import config
import time

#The base url for metadefender
base = "https://api.metadefender.com/v4/ip/"

#Headers sent with each request to authenticate
headers = {
    'apikey': config.md_api_key
}

#IP list to test
ip_list = ['124.156.62.15', '124.71.157.33', '69.63.176.13']

#The function Below takes the list of IPs and submits them to MetaDefender
def submit_url_md(ip_list):
    #Initialized dictionaries to use in the iterations below
    meta_results = {}
    meta_raw_results = []
    #A for loop submitting each url to MetaDefender
    for i in range(len(ip_list)):
        #While loop to keep trying if we get API errors
        while True:
            #try and except to catch any errors
            try:
                #setting the endpoint of each request to the url we are submitting
                end_point = ip_list[i]
                #adding the url to the base url
                url = base + end_point
                #sending the api request
                response = requests.get(url, headers=headers).json()
                #saving the response aligned to it's IP being the key in the dictionary
                meta_results[ip_list[i]] = response
                #adding each response to a list to save the raw api responses
                meta_raw_results.append(response)
                print("Submitted ip: ", ip_list[i], " to MetaDefender.")
            except:
                print("\nThe script was unable to parse the API response.")
                print("In case it was because we exceeded API Request Rate the script will retry in 30 second...")
                print("Below is the API error message for your reference:")
                print(response)
                print("")
                for j in range(30, 0, -1):
                    print(str(j), ' ', end='\r')
                    time.sleep(1)
                continue
            break
    return meta_results, meta_raw_results

# A functiona that takes the output of the API and provides a cleaner summary for each IP
def get_meta_summary(meta_results):
    #initlalized variables used in the iterations below
    sources = []
    results = {}
    assessment_dict = {}
    status_dict = {}

    #A for loop to iterate through each IP and save the sources key
    for i in range(len(ip_list)):
        #Takes just the dictionary of the response of the sources out for each IP
        extracts = meta_results[ip_list[i]]['lookup_results']['sources']
        #Adds the dictionary we extracted to a list
        sources.append(extracts)

    #A for loop that goes through each source we just extracted for each IP
    # and pulls the results out for each source
    for i in range(len(sources)):
        #To be able to pull the result out of each list
        source = sources[i]
        assessments = []
        status = []
        #A for loop to go through each 'assessment' result and 'status' result
        #It has if conditions to convert the api code to the code definiton
        #It then appends the result to a list
        for d in source:
            results.update(d)
            if results['assessment'] == '':
                assessments.append("No threat detected")
            else:
                assessments.append(results['assessment'])
            if results['status'] == 0:
                status.append('Whitelisted')
            elif results['status'] == 1:
                status.append('Blacklisted')
            elif results['status'] == 3:
                status.append('Failed to Scan')
            elif results['status'] == 5:
                status.append('Unknown')

        #The lines below create a dictionay of the IP being the key and the
        # list of the source results being their value
        assessment_dict[ip_list[i]] = assessments
        status_dict[ip_list[i]] = status

    #initialized variables for the next iterations
    assessment_summary = {}
    status_summary =  {}
    #A for loop to go through the list of IPs
    for i in range(len(ip_list)):
        total_assessments = assessment_dict[ip_list[i]]
        final_assessment = {}
        #The for loop below goes through the dictionary we made 'assessment_dict' in
        # the for loop above the one this one is nested in. Its going to add up each
        # duplicate result and provide a end total
        for j in total_assessments:
            # If element exists in dict then increment its value else add it in dict
            if j in final_assessment:
                final_assessment[j] += 1
            else:
                final_assessment[j] = 1
            assessment_summary[ip_list[i]] = final_assessment

        #The nested for loops below are the same as above but for the dictionary 'status_dict'
        for i in range(len(ip_list)):
            total_status = status_dict[ip_list[i]]
            final_assessment = {}
            for j in total_status:
                # If element exists in dict then increment its value else add it in dict
                if j in final_assessment:
                    final_assessment[j] += 1
                else:
                    final_assessment[j] = 1
                status_summary[ip_list[i]] = final_assessment
        print("Summarizing the scan report for ip: ", ip_list[i], "from MetaDefender.")
    return assessment_summary, status_summary

#This function lets us just use one function providing just the IPs to the script
def meta_scan(ip_list):
    #Submits the IP to MetaDefender with the first function
    meta_results, meta_raw_results = submit_url_md(ip_list)
    #Submits the results of the first function into the second function
    assessment_summary, status_summary = get_meta_summary(meta_results)
    #Converts the raw results to a nicer json format
    meta_results = json.dumps(meta_results, indent=4)
    return meta_results, assessment_summary, status_summary

#Calling the meta_scan function and submitting the list of IPs
meta_raw_results, assessment_summary, status_summary = meta_scan(ip_list)

print("\nBelow is a summmary result from MetaDefender:\n")
print(assessment_summary)
print("\n--------------------------------------------------------------------------------------\n")
print(status_summary)
print("\n--------------------------------------------------------------------------------------")
print("\n Below is the raw response for each IP from MetaDefender:\n")
print(meta_raw_results)