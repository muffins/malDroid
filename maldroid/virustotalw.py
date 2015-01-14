"""
Virus Total Submission Wrapper
This program submits samples to VirusTotal and returns the report.
"""

import urllib
import urllib2
import hashlib
import time
import json
import sys

from maldroid_conf import *

class VTWrapper:
    debug   = True
    fname   = ''
    fbuffer = ''
    digest  = ''
    baseurl = "https://www.virustotal.com/vtapi/v2/file/"
    sleeptime = 45


    # Constructor for VT Wrapper class.  Is it really necessary to give the hash?
    def __init__(self, fname, dbg=False):
        self.debug   = dbg
        self.fname   = fname
        self.fbuffer = open(self.fname, 'rb').read()
        self.digest  = hashlib.sha256(self.fbuffer).hexdigest()

    # Function which performs the main submission to VirusTotal
    def submit(self):
        # Attempt to get the report from VirusTotal
        params  = urllib.urlencode({"resource":self.digest, "apikey":APIKEY})
        request = urllib2.Request(self.baseurl+"report", params)
        resp    = json.loads(urllib2.urlopen(request).read())

        # If the report was indeed present and it could be retrieved it will be 1
        if resp['response_code'] == 1:
            # Get the time the report was submitted
            report_time = int(resp['scan_id'].split("-")[1])

            if self.debug: print "[+] Sample found! Report submitted on {}".format(time.strftime("%D %H:%M:%S",time.localtime(report_time)))

            # If the report is more than 1 week old
            if (int(time.time()) - report_time) > 604800:
                if self.debug: print "[-] Report is more than 1 week old, resubmitting. . ."

                # Resubmit the file for scanning
                request = urllib2.Request(self.baseurl+"rescan", params)
                resp    = json.loads(urllib2.urlopen(request).read())
                scan_id = resp['scan_id']

                # Attempt to get the report for the rescan
                params  = urllib.urlencode({"resource":scan_id, "apikey":APIKEY})
                request = urllib2.Request(self.baseurl+"report", params)
                resp    = json.loads(urllib2.urlopen(request).read())
                while resp['response_code'] == -2:
                    if self.debug: print "[-] Report is not ready. Sleeping for {} minutes.".format(self.sleeptime)
                    time.sleep(self.sleeptime)
                    # Re-encode the parameters, using the scan_id we obtain from the resubmission
                    params  = urllib.urlencode({"resource":scan_id, "apikey":APIKEY})
                    request = urllib2.Request(self.baseurl+"report", params)
                    resp    = json.loads(urllib2.urlopen(request).read())

        # The sample is not present. Submit it and wait for the report.
        elif resp['response_code'] == 0:
            fields = [("apikey", APIKEY)]
            files = [("file", self.fname, self.fbuffer)]
            resp = postfile.post_multipart("www.virustotal.com", self.baseurl+"scan", fields, files)
            # Wait for the scan to complete.
            while resp['response_code'] == -2:
                if self.debug: print "[-] Report is not ready. Sleeping for 2 minutes."
                time.sleep(self.sleeptime)
                params  = urllib.urlencode({"resource":resp['scan_id'], "apikey":APIKEY})
                request = urllib2.Request(self.baseurl+"report", params)
                resp    = json.loads(urllib2.urlopen(request).read())

        # The file is currently being analyzed. Wait for finish. Note: This shouldn't likely... ever happen.
        elif resp['response_code'] == -2:
            while resp['response_code'] == -2:
                if self.debug: print "[-] Report is not ready. Sleeping for {} minutes.".format(self.sleeptime)
                time.sleep(self.sleeptime)
                params  = urllib.urlencode({"resource":resp['scan_id'], "apikey":APIKEY})
                request = urllib2.Request(self.baseurl+"report", params)
                resp    = json.loads(urllib2.urlopen(request).read())

        # If the response code isn't 0, 1, or -2, then it's not currently defined by the VT API doc.
        else:
            if self.debug: print "[-] Undefined response code from API."
            resp = {}

        # Return the response of the scan in a JSON format.
        if self.debug: print "[+] Completed scanning sample. Returning Report."
        return resp

# For Standalone submissions
if __name__ == "__main__":
    # Debug
    if len(sys.argv) == 3:
        vt = VTWrapper(sys.argv[1], True)
        print "[+] VT Scan Results:\n{}".format(json.dumps(vt.submit()))

    # No Debugg
    elif len(sys.argv) == 2:
        vt = VTWrapper(sys.argv[1], False)
        print "[+] VT Scan Results:\n{}".format(json.dumps(vt.submit()))

    # Default usage
    else:
        print "Usage: python virustotal.py FileName [Debug]"
        sys.exit()
