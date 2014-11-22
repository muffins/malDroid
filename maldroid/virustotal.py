""" 
This module is used to interact with VirusTotal. VirusTotal defines 3 important API functions which we take advantage here: 
Sending and Scanning (upload), Rescanning (rescan), Retrieving Report (report). VirusTotal suggests checking if a "recent" report
is already available before uploading or rescaning which is what we do here - by recent we take it to be at most 3 days old. If the report
is available but not "recent" a rescan is performed. If it is not available an upload is performed. VirusTotal states  
"Keep in mind that files sent using the API have the lowest scanning priority, depending on VirusTotal's load, 
it may take several hours before the file is scanned, so query the report at regular intervals until the result shows up and do not keep sending the file once and over again" 
In this case we wait 15 seconds and try again to retrieve the report after it is queued both after a rescan or upload.

Things still need to work on: 

Handle 204 HTTP status code when request limit has been exceeded (limited to 4 requests in a minute)

Handle HTTP Error 403 Forbidden when performing calls to functions for which you do not have the required privileges --> we shouldn't need to do this

Still need to test uploading

What to do if report takes too long e.g. more than 10 minutes maybe?

Parsing of the returned report by Submitter.

General Error Checking

"""
import hashlib
import postfile
import time
import urllib
import urllib2
import simplejson


from maldroid_conf import *

DEBUG = False

#Uploads file to VirusTotal. Returns response from VirusTotal  --> HELPER FUNCTION
def upload(fname, fbuffer):
	host = "www.virustotal.com"
	selector = "https://www.virustotal.com/vtapi/v2/file/scan"
	fields = [("apikey", APIKEY)]
	files = [("file", fname, fbuffer)]
	json = postfile.post_multipart(host, selector, fields, files)
	return simplejson.loads(json)

#Get (or try to get) report using resource (hash or scan_id). Returns response from VirusTotal --> HELPER FUNCTION
def report(resource):
	url = "https://www.virustotal.com/vtapi/v2/file/report"
	parameters = {"resource": resource, "apikey": APIKEY}
	data = urllib.urlencode(parameters)
	req = urllib2.Request(url, data)
	response = urllib2.urlopen(req)
	json = response.read()
	return simplejson.loads(json)

#Performs a rescan, instead of just uploading, using resource (hash or scan_id). Returns response from VirusTotal --> HELPER FUNCTION
def rescan(resource):
	url = "https://www.virustotal.com/vtapi/v2/file/rescan"
	parameters = {"resource": resource, "apikey": APIKEY}
	data = urllib.urlencode(parameters)
	req = urllib2.Request(url, data)
	response = urllib2.urlopen(req)
	json = response.read()
	return simplejson.loads(json)


#Main function which should be used to return a report in JSON format given a file.    		
def Submitter(apk_file):
	
	apk_buffer = open(apk_file, "rb").read()
	#apk_buffer = open("./samples/malicious/SMSZombie/40F3F16742CD8AC8598BF859A23AC290.apk", "rb").read()

	#Compute sha256 hash over given file
	hash = hashlib.sha256(apk_buffer).hexdigest()
	
	#Check if file was already submitted. If not response_code == 0 	
	initial_chk = report(hash)


	if initial_chk['response_code'] == 1:
		
		tuple_id = initial_chk['scan_id'].split("-")
		retn_time = int(tuple_id[1])
		curr_time = int(time.time())

		#If file was already submitted and report is available, check if it is recent. less than 3 days		
		if (curr_time - retn_time) < 259200: # 3 Days

			if DEBUG:
				print "Recent report was found without needing to upload file!!"
			
			#Return report in JSON format 
			return simplejson.dumps(initial_chk)

		else:
			#try block ?
			#If already submitted but report is not recent rescan. 
			rescan_res = rescan(hash)
			report_chk = report(rescan_res['scan_id'])

			#Continue checking for until report is finished
			while report_chk['response_code'] == -2:
				
				if DEBUG:
					print "Report not ready will try agin in 15 seconds ... "				

				time.sleep(15)
				report_chk = report(rescan_res['scan_id'])

			if DEBUG:
				print "Scan finised!!!"

			#Return report in JSON format
			return simplejson.dumps(report_chk)

	else:

		if DEBUG:
			print "Uploading ... "			
		
		#Upload file to VT since it wasn't available		
		upload_res = upload(apk_file, apk_buffer)
		

		#upload_res = upload("./samples/malicious/SMSZombie/40F3F16742CD8AC8598BF859A23AC290.apk", apk_buffer)		
			

		upload_chk = report(upload_res['scan_id'])

		#Continue checking for until report is finished
		while upload_chk['response_code'] == -2

			if DEBUG:
				print "Report not ready will try agin in 15 seconds ... "

			time.sleep(15)
			upload_chk = report(upload_res['scan_id']


		if DEBUG:
			print "Scan finised!!!"

		#Return report in JSON format
		return simplejson.dumps(upload_chk)

