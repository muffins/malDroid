"""

	malDroid.py

	malDroid is a project dedicated to open source mobile malware analysis.  This
	projects goals are to provide forensic investigators and malware analysts with
	approachable information regarding the behavior of potentially malicious APK
	files.

	This project is still under *heavy* construction ;)

	Nick Anderson		- muffins@isis.poly.edu
	Michael Thompson	- mt1553@nyu.edu

"""

import os
import sqlite3
import hashlib
import multiprocessing
import json
import time
from analyze import analyze
from analysisdriver import MAEngine
from time import gmtime, strftime
from flask import Flask, request, session, g, redirect, url_for, abort, render_template, flash
from werkzeug import secure_filename
from maldroid_conf import *



""" Flask application configuration """
app = Flask(__name__)
app.config.from_object(__name__)
""" Init the DB Path """
SQLITE_DB = os.path.join(app.root_path, SQLITE_DB)
#print "[DBG] Path to sqlite DB {}".format(SQLITE_DB)
app.config.update(dict(
	DATABASE = SQLITE_DB,
	DEBUG = True,
	UPLOAD_FOLDER = UPLOAD_FOLDER,
	MAX_CONTENT_LENGTH = MAX_UPLOAD_SIZE
	))


""" Connect to the sqlite db """
def connect_db():
	rv = sqlite3.connect(app.config['DATABASE'])
	rv.row_factory = sqlite3.Row
	return rv


""" Getter function for the DB connection """
def get_db():
	if not hasattr(g, 'sqlite_db'):
		g.sqlite_db = connect_db()
	return g.sqlite_db


""" Close the Database when not in use """
@app.teardown_appcontext
def close_db(error):
	if hasattr(g, 'sqlite_db'):
		g.sqlite_db.close()


""" Function to stand up the Database and the uploads folder """
def init_app():
	with app.app_context():
		db = get_db()
		with app.open_resource('schema.sql', mode='r') as f:
			db.cursor().executescript(f.read())
		db.commit()
	if not os.path.exists(UPLOAD_FOLDER):
		os.makedirs(UPLOAD_FOLDER)


# TODO: Make this more robust, call to 'file' and parse results,
# find some way to ensure the file is a .APK before commiting to
# analysis.
""" Function to ensure that uploaded file is an APK """
def allowed_file(fname):
	return '.' in fname and fname.split('.')[-1] == 'apk'


""" Route for uploading sample """
@app.route('/upload', methods=['POST'])
def upload():
	if request.method == 'POST':
		file = request.files['file']
		if file and allowed_file(file.filename):
			fname = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(file.filename))
			# TODO: Potential issue. What happens if I upload different
			# files with the same name?
			file.save(fname)
			return redirect(url_for('analyze', fname=fname))
	return redirect(url_for('invalid_file'))


""" Route to begin analysis of sample. """
@app.route('/analyze')
def analyze():
	full_apk_name = request.args.get('fname')
	tstamp  = int(time.time())
	apkname = os.path.basename(full_apk_name)
	sha     = hashlib.sha256(open(full_apk_name,'r').read()).hexdigest()

	""" Here is where we'll run all of the malware analysis modules """

	MAE = MAEngine(full_apk_name, sha, SQLITE_DB)
	p = multiprocessing.Process(target=MAE.run_tests, args=())
	p.start()

	""" End malware analysis """

	# Insert the results into the DB
	db  = get_db()
	cur = db.cursor()

	# Ensure that this sample hasn't already been by the DB.
	cur.execute('SELECT * FROM reports WHERE digest=?', (sha,))
	if not cur.fetchall():
		# Note that we use a place holder for the report, this will be
		# updated later.
		cur.execute('INSERT INTO reports (digest, comname, tstamp, report)\
		 VALUES (?,?,?,?)', (sha, apkname, tstamp, ""))
	db.commit()
	return redirect(url_for('submission', fname=apkname, sum=sha))


""" Given a specific report, generate the report """
@app.route('/genreport', methods=['GET', 'POST'])
def genreport():
	db  = get_db()
	cur = db.cursor()
	r   = request.args.get('selectedreport')
	cur.execute('SELECT digest, comname, report, tstamp \
	 	FROM reports WHERE digest=?', (r,))
	# TODO: What happens if we get more than one : \
	# we could just use fetchone... We need to ensure
	# that it will never be the
	# wait. we shouldn't ever get more than one, as we already
	# check for this above...
	#rep = cur.fetchall()[0]
	rep = cur.fetchone()
	return render_template('genreport.html', report=rep)


""" Route for the reporting engine """
@app.route('/reports')
def reports():
	# Display a selection of all possible reports.
	db   = get_db()
	cur  = db.cursor()
	cur.execute('SELECT * FROM reports ORDER BY tstamp desc')
	reps = cur.fetchall()
	return render_template('reports.html', reports=reps)


""" Main page, index.html """
@app.route('/')
@app.route('/home')
def home():
	return render_template('index.html')


""" Contact form """
@app.route('/contact')
def contact():
	return render_template('contact.html')


""" About form """
@app.route('/about')
def about():
	return render_template('about.html')


""" Error page, used for invalid files """
@app.route('/invalid_file')
def invalid_file():
	return render_template('invalid_file.html')


""" intermediary page, used for placeholder after file submit """
@app.route('/submission')
def submission():
	app_name = request.args.get('fname')
	sha_sum  = request.args.get('sum')
	return render_template('submission.html',appname=app_name, digest=sha_sum)


""" Generic error page """
@app.route('/error')
def error():
	return render_template('error.html')


""" Start the app """
if __name__ == '__main__':
	init_app()
	app.run()
