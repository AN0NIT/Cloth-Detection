from flask_app import db
import os

if not os.path.isfile("database.db"):
    f = open('database.db','w')
    f.close()
db.create_all()
