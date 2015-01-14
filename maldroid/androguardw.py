"""
This program acts as a wrapper for the Angroguard toolset. It runs Androguard
utilities and returns the results of the scans.
"""
import sys
import os

from androguard.core import androconf
from androguard.core.bytecodes import apk
from androguard.core.analysis import risk
from elsim.elsign import dalvik_elsign

class AndroguardW:
    app     = ''
    fname   = ''
    debug   = True
    isvalid = True

    def __init__(self, fname, dbg=False):
        self.fname = fname
        self.debug = dbg
        if androconf.is_android(self.fname) == 'APK':

            # Try to cast the application as an Android APK
            try: self.app = apk.APK(fname)

            # If the file isn't an Android application, set a variable so we know
            except Exception, e:
                if self.debug: print "[-] File was not a valid Android Application!"
                self.isvalid = False
            if not self.app.is_valid_APK():
                self.isvalid = False

    #
    # TODO: We're not currently using this. Let's find a DB and hook it up :-D
    #
    # Checks the given sample against a database to see if it is already listed as
    # Malware. Different databases can be used to have up-to-date results. Returns
    # "None" if not in the database or it returns the common name of the malware sample
    def check_db(self):
        if self.isvalid:
            signature = dalvik_elsign.MSignature('signatures/dbandroguard', 'signatures/dbconfig', False, ps=dalvik_elsign.PublicSignature)
            return signature.check_apk(self.app)
        else:
            if self.debug: print "[-] File was not a valid Android Application!"
            return ''

    # Returns the permissions requested in the manifest file. Also provides a
    # detailed description of what the permissions allow the application to do
    # as well as whether it is dangerous.
    def check_permissions(self):
        if self.isvalid:
            return self.app.get_details_permissions()
        else:
            if self.debug: print "[-] File was not a valid Android Application!"
            return ''

    # Returns all activites registered by the android application
    def check_activities(self):
        if self.isvalid:
            return self.app.get_activities()
        else:
            if self.debug: print "[-] File was not a valid Android Application!"
            return ''

    # Returns all registered services by the application
    def check_services(self):
        if self.isvalid:
            return self.app.get_services()
        else:
            if self.debug: print "[-] File was not a valid Android Application!"
            return ''

    # Returns a 'Fuzzy Risk' value for how potentially malicious the app is
    def check_risk(self):
        if self.isvalid:
            ri = risk.RiskIndicator()
            ri.add_risk_analysis(risk.RedFlags())
            ri.add_risk_analysis(risk.FuzzyRisk())
            return ri.with_apk(self.app)
        else:
            if self.debug: print "[-] File was not a valid Android Application!"
            return ''


if __name__ == "__main__":
    aw = ''
    if len(sys.argv) == 3: # Debug
        aw = AndroguardW(sys.argv[1], True)
    elif len(sys.argv) == 2: #
        aw = AndroguardW(sys.argv[1], False)
    else:
        print "Usage: python androguardw.py app.apk [debug]"
        sys.exit()
    print "[+] Androguard Check DB: {}".format(aw.check_db())
    print "[+] Androguard Check Permissions: {}".format(aw.check_permissions())
    print "[+] Androguard Check Activites: {}".format(aw.check_activities())
    print "[+] Androguard Check Services: {}".format(aw.check_services())
    print "[+] Androguard Check Risk: {}".format(aw.check_risk())
