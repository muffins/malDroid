import os
"""

    Configuration file for malDroid.  This file contains
    any global variables that are shared between various classes.

"""
MAX_UPLOAD_SIZE = 32 * 1024 * 1024 # Limit upload size to 30MB
UPLOAD_FOLDER   = os.path.join(os.getcwd(), 'uploads/apk_samples')
SQLITE_DB       = "maldroid.db"
