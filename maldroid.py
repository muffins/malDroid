# all the imports
import os
import sqlite3
from time import gmtime, strftime
from flask import Flask, request, session, g, redirect, url_for, abort, render_template, flash
from werkzeug import secure_filename

# Create and Configure the flask app
app = Flask(__name__)
UPLOAD_FOLDER = './uploads/apk_samples'
app.config.from_object(__name__)
app.config.update(dict(
	DATABASE = os.path.join(app.root_path, 'maldroid.db'),
	DEBUG = True,
	UPLOAD_FOLDER = UPLOAD_FOLDER,
	MAX_CONTENT_LENGTH = 32 * 1024 * 1024 # Limit upload size to 30MB
	#SECRET_KEY = '',,
	#USERNAME = '',
	#PASSWORD = ''
	))


app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024


""" Connect to the sqlite db """
def connect_db():
	rv = sqlite3.connect(app.config['DATABASE'])
	rv.row_factory = sqlite3.Row
	return rv


# Open the DB connection if it doesn't already exist
def get_db():
	if not hasattr(g, 'sqlite_db'):
		g.sqlite_db = connect_db()
	return g.sqlite_db


# Close the DB connection at the end of requests.
@app.teardown_appcontext
def close_db(error):
	if hasattr(g, 'sqlite_db'):
		g.sqlite_db.close()


# Setup the database.
def init_db():
	with app.app_context():
		db = get_db()
		with app.open_resource('schema.sql', mode='r') as f:
			db.cursor().executescript(f.read())
		db.commit()


# At some point, this needs to be refined, to ensure that the
# file itself is appropriate to be on our server, as opposed to
# having a proper file extension :P
def allowed_file(fname):
	return '.' in fname and fname.split('.')[-1] == 'apk'


@app.route('/upload', methods=['GET','POST'])
def upload():
	if request.method == 'POST':
		file = request.files['file']
		if file and allowed_file(file.filename):
			fname = secure_filename(file.filename)
			file.save(os.path.join(app.config['UPLOAD_FOLDER'], fname))
			return redirect(url_for('report', fname=fname))
	return redirect(url_for('invalid_file'))


#@app.route('/report', methods=['GET','POST'])
@app.route('/report')
def report():
	apkname = request.args.get('fname')
	return redirect(url_for('home'))


@app.route('/')
@app.route('/home')
def home():
	#db = get_db()
	#cur = db.execute('select title, text, timestamp from entries order by id desc')
	#entries = cur.fetchall()
	return render_template('index.html')

# Route for Contact form
@app.route('/contact')
def contact():
	return render_template('contact.html')

# Route for About form
@app.route('/about')
def about():
	return render_template('about.html')

# Page for invalid file type.
@app.route('/invalid_file')
def invalid_file():
	return render_template('invalid_file.html')

# Generic Error page.
@app.route('/error')
def error():
	return render_template('error.html')



# This is the default manner in which to uplpoad a file in flask.  Right
# now I'm just following the tutorial here: http://flask.pocoo.org/docs/0.10/patterns/fileuploads/
# but at some point we'll want to restrict this to very very very specifically
# android APKs, so that our server isn't being flooded with files :S
if __name__ == '__main__':
	app.run()


