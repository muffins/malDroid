malDroid
========

A web application for analysing potentially malicious Android applications.

### TODO:
 * Update the schema.sql

 * Design application reports, these should be inserted
   into the DB, and query-able via a hash of the APK

 * Design the view for reports :P

 * Create a list of APK scanners/analysis engines/things we can use
   to scan and generate our reports.
   - Virus Total
   - Andrubis
   - Androguard
   - DroidScope
   - Static Analysis, via dex2jar and static Java analysis
     -- Radare2 has some potential.
