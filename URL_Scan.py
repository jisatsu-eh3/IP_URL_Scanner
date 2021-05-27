from virus_total_apis import PublicApi as VirusTotalPublicApi
import requests
import time
import json
import config


#The base url for metadefender
base = "https://api.metadefender.com/v4/ip/"

#Headers sent with each request to authenticate
headers = {
    'apikey': config.md_api_key
}

#IP list to test
ip_list = ['124.156.62.15', '124.71.157.33', '69.63.176.13']

#VT Api
vt = VirusTotalPublicApi(config.vt_api_key)

#initializing data
clean_results = []
scan_id_results = []
s_id = "scan_id"

#The function to pull the scan id out of the response from submitting the url
def get_scan_id(test_dict, key_list):
   for i, j in test_dict.items():
     if i in key_list:
        yield (i, j)
     yield from [] if not isinstance(j, dict) else get_scan_id(j, key_list)

#Function to make a list from the keys of a dictionary
def getList(dict):
    return list(dict.keys())

#----------------------------------------------------------------------------------------------------------------------
#MetaDefender API

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

#----------------------------------------------------------------------------------------------------------------------
# VT API

def get_vt_jobid_for_url(ip_list):
    # For loop to iterate through the list of IP
    for i in range(len(ip_list)):
        while True:
            try:
                #Submits the IP to virus total and saves response to initial scan
                initial_scan = vt.scan_url(ip_list[i])
                time.sleep(12)
                #Uses the function to get the scan ID dictionary
                scan_dict = dict(get_scan_id(test_dict = initial_scan, key_list = s_id))
                #Adds the scan IDs to a list
                scan_id_results.append(scan_dict['scan_id'])
                print("Submitted ip: ", ip_list[i], " to Virus Total.")
            except:
                print("\nThe script was unable to parse the API response.")
                print("In case it was because we exceeded API Request Rate the script will retry in 30 second...")
                print("Below is the API error message for your reference:")
                print(initial_scan)
                print("")
                for j in range(30, 0, -1):
                    print(str(j), ' ', end='\r')
                    time.sleep(1)
                continue
            break
    return scan_id_results

def submit_vt_jobid(ip_list, scan_id_results):
    #Initialize some needed variable for the output of the scan_id
    raw_report = []
    sources = []
    ip_to_scan = {}
    ip_to_sources = {}

    source_result_dict = {}
    ip_to_scan_results = {}
    ip_to_result_dict = {}

    #For loop that submits the scan ID for output
    for i in range(len(ip_list)):
        while True:
            try:
                #The line below submits the scan_id to VT for respons
                report_result = vt.get_url_report(ip_list[i], scan=scan_id_results[i])
                time.sleep(12)
                #Appends each response to a list so we can see the complete raw report
                raw_report.append(report_result)
                #Makes a dictionary of the just the scans
                scans = report_result['results']['scans']
                # Makes a list of the sources for the scan
                sources.append(getList(scans))
                # Adding to the dictionary the list of scan results aligned to their IP
                ip_to_scan[ip_list[i]] = scans
                # Adding to the dictionary the list of sources that provided results aligned to the IP
                ip_to_sources[ip_list[i]] = sources[0]
                print("Submitted the job id for the ip: ", ip_list[i], " to Virus Total.")
            except:
                print("\nThe script was unable to parse the API response.")
                print("In case it was because we exceeded API Request Rate the script will retry in 30 second...")
                print("Below is the API error message for your reference: ")
                print(report_result)
                print("")
                for j in range(30, 0, -1):
                    print(str(j), ' ', end='\r')
                    time.sleep(1)
                continue
            break

    #For loop to create lists or dictionaries needed
    for i in range(len(ip_list)):
        #The line below takes the results for each IP
        result_by_ip = ip_to_scan[ip_list[i]]
        print("Summarizing the scan report for ip: ", ip_list[i], "from Virus Total.")
        #The line below makes a list of sources for each ip
        keys_by_ip = [getList(result_by_ip)]
        #Cleans up the list made from above
        keys_by_ip = keys_by_ip[0]
        #for loop to go through each IP
        ip_to_scan_results[ip_list[i]] = result_by_ip

    for i in range(len(ip_list)):
        result_extract = ip_to_scan_results[ip_list[i]]
        source_results = []
        for j in range(len(result_extract)):
            #The line below extracts the results from each source to a list
            ip_to_result_dict[ip_list[i]] = source_results.append(result_extract[keys_by_ip[j]]['result'])
        #The line below then makes a dictionary  entry for each IP aligned to the results
        source_result_dict[ip_list[i]] = source_results

    #initializing more variables for the next iteration
    final_report = {}
    ip_to_output = {}
    result_output = []
    #The for loop below iterates through the list of IPs
    for i in range(len(ip_list)):
        #The line below assigns the result of one of the IPs to out
        output = source_result_dict[ip_list[i]]
        ip_to_output[ip_list[i]] = output
        result_output.append(output)

    #The line below makes a dictionary counts the number of instances for each item in the list
    for i in range(len(ip_list)):
        Summary = dict((x,result_output[i].count(x)) for x in set(result_output[i]))
        final_report[ip_list[i]] = Summary

    report_json = json.dumps(final_report, indent = 4)
    raw_report_json = json.dumps(raw_report, indent = 4)
    return report_json, raw_report_json

#This function lets us just use one function providing just the IPs to the script
def meta_scan(ip_list):
    #Submits the IP to MetaDefender with the first function
    meta_results, meta_raw_results = submit_url_md(ip_list)
    #Submits the results of the first function into the second function
    assessment_summary, status_summary = get_meta_summary(meta_results)
    #Converts the raw results to a nicer json format
    meta_results = json.dumps(meta_results, indent=4)

    return meta_results, assessment_summary, status_summary

def vt_url_scan(ip_list):
    scan_results = get_vt_jobid_for_url(ip_list)
    summary, raw = submit_vt_jobid(ip_list, scan_results)

    return summary, raw

vt_clean_summary, vt_raw_report = vt_url_scan(ip_list)

#Calling the meta_scan function and submitting the list of IPs
meta_raw_results, assessment_summary, status_summary = meta_scan(ip_list)


print("\nBelow is a summmary result from Virus Total\n")
print(vt_clean_summary)
print()
print("--------------------------------------------------------------------------------------")
print("\n Below is the raw reponse for each IP from Virus Total\n")
print(vt_raw_report)

print("\nBelow is a summmary result from MetaDefender:\n")
print(assessment_summary)
print("\n--------------------------------------------------------------------------------------\n")
print(status_summary)
print("\n--------------------------------------------------------------------------------------")
print("\n Below is the raw response for each IP from MetaDefender:\n")
print(meta_raw_results)
