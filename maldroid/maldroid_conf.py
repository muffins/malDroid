import os
"""

    Configuration file for malDroid.  This file contains
    any global variables that are shared between various classes.

    ---> ADDED APIKEY TO SUPPORT VirusTotal Module (virustotal.py)

"""
MAX_UPLOAD_SIZE = 32 * 1024 * 1024 # Limit upload size to 30MB
UPLOAD_FOLDER   = os.path.join(os.getcwd(), 'uploads/apk_samples')
SQLITE_DB       = "maldroid.db"
APIKEY		= "1b5439e68266c59ffc4972a08dc77614cfe69440d9672c5cf77cb94cee7bac6d"  #Used to authenticate connections with VirusTotal
