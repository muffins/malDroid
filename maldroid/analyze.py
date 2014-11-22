""" Main class used to perform different malware analysis functions """
import sys
import os

from androguard.core import androconf
from androguard.core.bytecodes import apk
from androguard.core.analysis import risk
from elsim.elsign import dalvik_elsign


class analyze:

    def __init__(self, fname):
        self.fname = fname

        ret_type = androconf.is_android(self.fname)

        if ret_type == 'APK':
            try:
                self.a = apk.APK(fname)
            except Exception, e:
                print 'ERROR', e
        else:
            return 'Not an APK file'
    
    """ 
    Checks the given sample against a database to see if it is already listed as Malware. Different databases can be used
    to have up-to-date results. Returns "None" if not in the database or it returns the common name of the malware sample
    
    """

    def check_db(self):

        s = dalvik_elsign.MSignature('signatures/dbandroguard',
                'signatures/dbconfig', False,
                ps=dalvik_elsign.PublicSignature)

        if self.a.is_valid_APK():
            return s.check_apk(self.a)
        else:
            print 'INVALID'
    
    """ 
    Returns the permissions requested in the manifest file. Also provides a detailed description of what the permissions 
    allow the application to do as well as whether it is dangerous.
 
    """
   
    def check_permissions(self):

        if self.a.is_valid_APK():
            return self.a.get_details_permissions()
        else:
            print 'INVALID'

    def check_activities(self):

        if self.a.is_valid_APK():
            return self.a.get_activities()
        else:
            print 'INVALID'

    def check_services(self):

        if self.a.is_valid_APK():
            return self.a.get_services()
        else:
            print 'INVALID'

    """ """

    def check_risk(self):

        ri = risk.RiskIndicator()
        ri.add_risk_analysis(risk.RedFlags())
        ri.add_risk_analysis(risk.FuzzyRisk())

        if self.a.is_valid_APK():
            return ri.with_apk(self.a)
        else:
            print 'INVALID'
