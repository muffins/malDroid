# all the imports
import os
import sqlite3
from time import gmtime, strftime
from flask import Flask, request, session, g, redirect, url_for, abort, \
     render_template, flash

app = Flask(__name__)
app.config.from_object(__name__)

app.config.update(dict(
	DATABASE = os.path.join(app.root_path, 'maldroid.db'),
	DEBUG = True,
	SECRET_KEY = 'd3v3lopm3nt_k3y',
	USERNAME = 'admin',
	PASSWORD = 'default'
	))


""" Connect to the sqlite db """
def connect_db():
	rv = sqlite3.connect(app.config['DATABASE'])
	rv.row_factory = sqlite3.Row
	return rv


""" Opens a brand new database connection if one doesn't presently exist for the current
application context """
def get_db():
	if not hasattr(g, 'sqlite_db'):
		g.sqlite_db = connect_db()
	return g.sqlite_db


""" Closes the db again at the end of a request """
@app.teardown_appcontext
def close_db(error):
	if hasattr(g, 'sqlite_db'):
		g.sqlite_db.close()


""" Initialize the Database """
def init_db():
	with app.app_context():
		db = get_db()
		with app.open_resource('schema.sql', mode='r') as f:
			db.cursor().executescript(f.read())
		db.commit()


@app.route('/')
@app.route('/index.html')
def show_entries():
	db = get_db()
	cur = db.execute('select title, text, timestamp from entries order by id desc')
	entries = cur.fetchall()
	return render_template('show_entries.html', entries=entries)


@app.route('/add', methods=['POST'])
def add_entry():
	current_time = strftime("%a, %d %b %Y %H:%M:%S", gmtime())
	if not session.get('logged_in'):
		abort(401)
	db = get_db()
	db.execute('insert into entries (title, text, timestamp) values (?, ?, ?)',
		[request.form['title'], request.form['text'], current_time])
	db.commit()
	flash('New entry was successfully posted')
	return redirect(url_for("show_entries"))


@app.route('/login', methods=['GET', 'POST'])
def login():
	error = None
	if request.method == 'POST':
		if request.form['username'] != app.config['USERNAME'] or request.form['password'] != app.config['PASSWORD']:
			error = 'Invalid Logon Credentials'
		else:
			session['logged_in'] = True
			flash('You have been successfully logged in')
			return redirect(url_for('show_entries'))
	return render_template('login.html', error=error)


@app.route('/logout')
def logout():
	session.pop('logged_in', None)
	flash('You were logged out')
	return redirect(url_for('show_entries'))


if __name__ == '__main__':
	app.run()


