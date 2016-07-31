import argparse
import bcrypt
import socket
import subprocess
import sys

from shlex import quote

from flask import Flask, abort, request
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import exc

VERBOSE = False
nsupdate_keyfile = 'ddns-key.conf'
nsupdate_server = ''
nsupdate_zone = ''

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
db = SQLAlchemy(app)

class User(db.Model):
		id = db.Column(db.Integer, primary_key=True)
		user = db.Column(db.String(80), unique=True)
		password = db.Column(db.Text())
		domain = db.Column(db.Text())
		last_ip = db.Column(db.String(64))

		def __init__(self, user, pw, domain):
				self.user = user
				self.password = pw
				self.domain = domain

		def __str__(self):
				return 'User: {}, Domain: {}'.format(self.user, self.domain)


def run_nsupdate(domain, ip):
		command = 'nsupdate -k {} -v <<EOF\n'.format(nsupdate_keyfile)
		command += 'server {}\n'.format(nsupdate_server)
		command += 'zone {}\n'.format(nsupdate_zone)
		command += 'update delete {} A \n'.format(quote(domain))
		command += 'update add {} 30 A {}\n'.format(quote(domain), quote(ip))
		command += 'send\n'
		command += 'EOF\n'

		if VERBOSE:
				print('Execute nsupdate: \n\n{}'.format(command))

		subprocess.run(command, shell=True)

@app.route('/update')
def update():
		username = request.args.get('username')
		password = request.args.get('password')
		ip = request.args.get('ip')
		domain = request.args.get('domain')

		if VERBOSE:
				print('New update request from {}, domain {}, ip {}\n'.format(username, domain, ip))

		# Query user and check password
		user = User.query.filter_by(user=username, domain=domain).first_or_404()
		if not password or not bcrypt.checkpw(password.encode('UTF-8'), user.password):
				abort(401)

		# Validate ip
		if not ip:
				abort(400)

		try:
				socket.inet_aton(ip)
		except socket.error:
				abort(400)

		user.last_ip = ip
		db.session.commit()

		run_nsupdate(user.domain, ip)

		return 'ok'

def add_user(username, pw, domain):
		hashed_pw = bcrypt.hashpw(pw.encode('UTF-8'), bcrypt.gensalt())
		u = User(username, hashed_pw, domain)
		db.session.add(u)
		try:
				db.session.commit()
				print('User {} added successfully'.format(username))
		except exc.IntegrityError:
				print('User {} already exists'.format(username))
				


if __name__ == "__main__":
		parser = argparse.ArgumentParser(description='DDNS updater')
		parser.add_argument('-a', nargs=3, help='Add user: -a <username> <password> <domain>', metavar=('user', 'password', 'domain'))
		parser.add_argument('-r', help='Run the server', action='store_const', const=True)
		parser.add_argument('-k', help='nsupdate keyfile', default='ddns-key.conf')
		parser.add_argument('-s', help='nameserver address')
		parser.add_argument('-z', help='nameserver zone')
		parser.add_argument('-v', help='verbose', action='store_true')
		args = parser.parse_args()

		if args.v:
				VERBOSE = True

		if args.r:
				if not args.s:
						print('No nameserver specified!')
						exit()
				if not args.z:
						print('No zone specified!')
						exit()

				nsupdate_keyfile = args.k
				nsupdate_server = args.s
				nsupdate_zone = args.z
				app.run()

		if args.a:
				add_user(args.a[0], args.a[1], args.a[2])

