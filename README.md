malDroid
========

A web application for analysing potentially malicious Android applications.

### TODO:

 * Integrate the Androguard file checker into our uploading functionality
   so we're verifying the file is an APK, as opposed to just checking
   the file extension

 * Create a list of APK scanners/analysis engines/things we can use
   to scan and generate our reports.
   - Virus Total
   - Andrubis
   - DroidScope
   - Static Analysis, via dex2jar and static Java analysis
     -- Radare2 has some potential.
