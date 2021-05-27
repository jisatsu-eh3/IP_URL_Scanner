from virus_total_apis import PublicApi as VirusTotalPublicApi
#from collections import Counter
import time
import json
import config

#IP list to test
ip_list = ['124.156.62.15', '124.71.157.33', '69.63.176.13']

#Api
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

# For loop to iterate through the list of IP
for i in range(len(ip_list)):
    while True:
        try:
            #Submits the IP to virus total and saves response to initial scan
            initial_scan = vt.scan_url(ip_list[i])
            time.sleep(10)
            #Uses the function to get the scan ID dictionary
            scan_dict = dict(get_scan_id(test_dict = initial_scan, key_list = s_id))
            #Adds the scan IDs to a list
            scan_id_results.append(scan_dict['scan_id'])
            print("Submitted url: ", ip_list[i])
        except:
            print("\nMade too many API requests, going to retry in 30 second...")
            print("Below is the API error message:")
            print(initial_scan)
            print("")
            for j in range(30, 0, -1):
                print(str(j), ' ', end='\r')
                time.sleep(1)
            continue
        break

#Initialize some needed variable for the output of the scan_id
raw_report = []
sources = []
ip_to_scan = {}
ip_to_sources = {}

#For loop that submits the scan ID for output
for i in range(len(ip_list)):
    while True:
        try:
            #The line below submits the scan_id to VT for respons
            report_result = vt.get_url_report(ip_list[i], scan=scan_id_results[i])
            time.sleep(10)
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
            print("Submitted the job id for the url: ", ip_list[i])
        except:
            print("\nMade too many API requests, going to retry in 30 second...")
            print("Below is the API error message:")
            print(report_result)
            print("")
            for j in range(30, 0, -1):
                print(str(j), ' ', end='\r')
                time.sleep(1)
            continue
        break


#Initialize more variables for next iteration
source_results = []
source_result_dict = {}
ip_to_scan_results = {}

#For loop to create lists or dictionaries needed
for i in range(len(ip_list)):
    #The line below takes the results for each IP
    result_by_ip = ip_to_scan[ip_list[i]]
    print("Summarizing the scan report for url: ", ip_list[i])
    #The line below makes a list of sources for each ip
    keys_by_ip = [getList(result_by_ip)]
    #Cleans up the list made from above
    keys_by_ip = keys_by_ip[0]
    #for loop to go through each IP
    ip_to_scan_results[ip_list[i]] = result_by_ip

ip_to_result_dict = {}

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
print("\nBelow is a summmary result from Virus Total\n")
print(report_json)
print()
print("--------------------------------------------------------------------------------------")
print("\n Below is the raw reponse for each IP\n")
print(raw_report_json)


