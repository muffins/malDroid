"""
This module is used to interact with VirusTotal. VirusTotal defines 3 important
API functions which we take advantage here:

 + Sending and Scanning (upload)
 + Rescanning (rescan)
 + Retrieving Report (report)

VirusTotal suggests checking if a "recent" report is already available before
uploading or rescaning which is what we do here - by recent we take it to be at
most 3 days old. If the report is available but not "recent" a rescan is performed.
If it is not available an upload is performed. VirusTotal states "Keep in mind
that files sent using the API have the lowest scanning priority, depending on
VirusTotal's load, it may take several hours before the file is scanned, so
query the report at regular intervals until the result shows up and do not
keep sending the file once and over again" In this case we wait 15 seconds
and try again to retrieve the report after it is queued both after a rescan or upload.

Things still need to work on:

* Handle 204 HTTP status code when request limit has been exceeded (limited to 4 requests in a minute)

* Handle HTTP Error 403 Forbidden when performing calls to functions for which you do not have the required privileges --> we shouldn't need to do this

* Still need to test uploading

* What to do if report takes too long e.g. more than 10 minutes maybe?

* Parsing of the returned report by Submitter.

* General Error Checking

"""
#import hashlib
import postfile
import time
import urllib
import urllib2
import simplejson

from maldroid_conf import *



class VTWrapper:
	DEBUG   = True
	fname   = ''
	fbuffer = ''
	digest  = ''

	def __init__(self, dbg, fname, digest):
		self.DEBUG   = dbg
		self.fname   = fname
		self.digest  = digest
		self.fbuffer = open(self.fname, 'rb').read()

	#Uploads file to VirusTotal. Returns response from VirusTotal  --> HELPER FUNCTION
	def upload(self):
		host = "www.virustotal.com"
		selector = "https://www.virustotal.com/vtapi/v2/file/scan"
		fields = [("apikey", APIKEY)]
		files = [("file", self.fname, self.fbuffer)]
		json = postfile.post_multipart(host, selector, fields, files)
		return simplejson.loads(json)

	#Get (or try to get) report using resource (hash or scan_id).
	#Returns response from VirusTotal --> HELPER FUNCTION
	def report(self, resource):
		url = "https://www.virustotal.com/vtapi/v2/file/report"
		parameters = {"resource": resource, "apikey": APIKEY}
		data = urllib.urlencode(parameters)
		req = urllib2.Request(url, data)
		response = urllib2.urlopen(req)
		json = response.read()
		return simplejson.loads(json)

	#Performs a rescan, instead of just uploading, using resource (hash or scan_id). Returns response from VirusTotal --> HELPER FUNCTION
	def rescan(self, resource):
		url = "https://www.virustotal.com/vtapi/v2/file/rescan"
		parameters = {"resource": resource, "apikey": APIKEY}
		data = urllib.urlencode(parameters)
		req = urllib2.Request(url, data)
		response = urllib2.urlopen(req)
		json = response.read()
		return simplejson.loads(json)


	#Main function which should be used to return a report in JSON format given a file.
	def Submitter(self):

		#XXX: We already have this
		#apk_buffer = open(apk_file, "rb").read()

		#Compute sha256 hash over given file
		#XXX: We already have this
		#self.digesthash = hashlib.sha256(apk_buffer).hexdigest()

		#Check if file was already submitted. If not response_code == 0
		initial_chk = report(self.digest)

		if self.DEBUG:
			print "[Initial] Initial check completed"
			print "[Initial] Response Code: ", initial_chk['response_code']

		if initial_chk['response_code'] == 1:

			tuple_id = initial_chk['scan_id'].split("-")
			retn_time = int(tuple_id[1])
			curr_time = int(time.time())

			#If file was already submitted and report is available, check if it is recent. less than 3 days
			if (curr_time - retn_time) < 259200: # 3 Days

				if self.DEBUG:
					print "[Recent] Recent report was found without needing to upload file!!"

				#Return report in JSON format
				return simplejson.dumps(initial_chk)

			else:
				if self.DEBUG:
					print "[Rescan] The last report was at: ", time.asctime( time.localtime(float(tuple_id[1])) )
					count = 0

				#try block ?
				#If already submitted but report is not recent rescan.
				rescan_res = self.rescan(self.digest)
				report_chk = self.report(rescan_res['scan_id'])

				#Continue checking for until report is finished
				while report_chk['response_code'] == -2:

					if self.DEBUG:
						print "[Rescan] Report not ready will try agin in 15 seconds ... "
						print "[Rescan] Response Code: ", report_chk['response_code']
						count += 1

					time.sleep(15)
					report_chk = self.report(rescan_res['scan_id'])

				if self.DEBUG:
					print "[Rescan] Scan finised!!!"
					print "[Rescan] Scan took %s seconds" % (count*15)
					print "[Rescan] Finally Response Code: ", report_chk['response_code']

				#Return report in JSON format
				return simplejson.dumps(report_chk)

		else:

			if self.DEBUG:
				print "[Upload] Uploading ... "

			#Upload file to VT since it wasn't available
			upload_res = self.upload()
			upload_chk = self.report(upload_res['scan_id'])

			if self.DEBUG:
				print "[Upload] Report check completed"
	                	print "[Upload] Response Code: ", upload_chk['response_code']
				count = 0

			#Continue checking for until report is finished
			while upload_chk['response_code'] == -2:

				if self.DEBUG:
					print "[Upload] Report not ready will try agin in 15 seconds ... "
					print "[Upload] Response Code: ", upload_chk['response_code']
					count += 1

				time.sleep(15)
				upload_chk = self.report(upload_res['scan_id'])


			if self.DEBUG:
				print "[Upload] Scan finised!!!"
				print "[Upload] Scan took %s seconds" % (count*15)
				print "[Upload] Finally Response Code: ", upload_chk['response_code']

			#Return report in JSON format
			return simplejson.dumps(upload_chk)
