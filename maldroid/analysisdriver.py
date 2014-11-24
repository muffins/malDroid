
from analyze import analyze # Wrapper for androguard scanning
#from virustotal import VTWrapper # wrapper for VirusTotal submission
from maldroid_conf import *

import os
import sys
import sqlite3
import json

"""
    This class is the primary malware analysis driver.
    It should take as it's only argument the full path
    to the Android Application. It returns either a detailed
    JSON report about the app, or an error in the instance
    where the app was not an Android APK, or if there were
    any parsing issues.

"""

class MAEngine():

    digest  = '' # digest of the sample, used to lookup the db entry
    apk     = '' # Place holder for the Androguard wrapper class
    vt      = '' # Place holder for the VirusTotal wrapper class
    rep     = {} # Place holder for the report generated.
    db_path = ''

    """ Init digest and APK variable """
    def __init__(self, app_name, s, db):
        self.digest = s
        self.apk = analyze(app_name)
        #self.vt  = VTWrapper(app_name, True, digest)
        self.db_path = db

    """
    This is the meat of the stew. All malware tests are launched here,
    and subsequently all report data should be fed back here. This function
    finishes executiong by calling the 'report' function, which simply updates
    the DB record with the 'report' which is really just a JSON blob
    """
    def run_tests(self):
        self.rep["androguard_perms"] = self.apk.check_permissions()
        self.rep["androguard_risk"]  = self.apk.check_risk()

        # Begin processing report once finished with analyses
        self.report()

    """ This function simply updates the DB entry with the JSON report """
    def report(self):
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute('UPDATE reports SET report=? WHERE digest=?', (json.dumps(self.rep), self.digest))
        conn.commit()
        conn.close()
