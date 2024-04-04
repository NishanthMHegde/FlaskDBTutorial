from app import db
from flask_login import UserMixin

class Person(db.Model):
	__tablename__ = "people"
	pid = db.Column(db.Integer, primary_key=True)
	name = db.Column(db.Text, nullable=False)
	age = db.Column(db.Integer)
	job = db.Column(db.Text)

	def __repr__(self):
		return "PID: %s, Name: %s, Age: %s, Job:%s" % (self.pid, self.name, self.age, self.job)

class User(db.Model, UserMixin):
	__tablename__ = "users"
	uid = db.Column(db.Integer, primary_key=True)
	username = db.Column(db.Text, nullable=False)
	password = db.Column(db.Text, nullable=False)
	role = db.Column(db.Text)
	description = db.Column(db.Text)

	def __repr__(self):
		return 'username: %s has a role %s' % (self.username, self.role)

	def get_id(self):
		return self.uid
