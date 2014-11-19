# Check_db and check_risk when result in a "KILLED" message after running for a VERY long time. Possibly my VM does not have enough resources
# Still need to work on those two methods
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

    def check_db(self):

        s = dalvik_elsign.MSignature('signatures/dbandroguard',
                'signatures/dbconfig', True,
                ps=dalvik_elsign.PublicSignature)

        if self.a.is_valid_APK():
            return s.check_apk(self.a)
        else:
            print 'INVALID'

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

    def check_risk(self):

        ri = risk.RiskIndicator()
        ri.add_risk_analysis(risk.RedFlags())
        ri.add_risk_analysis(risk.FuzzyRisk())

        if self.a.is_valid_APK():
            return ri.with_apk(self.a)
        else:
            print 'INVALID'


