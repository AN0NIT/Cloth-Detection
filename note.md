# inorder to start the database
- open "python" in cmd or ps
## import db from app.py like:
``from flask_app import db``
## then type:
``db.create_all()``
## Now open the database.db in sqlite3
``sqlite3 database.db``

## Check for table user, if it exists the DB is initialized properly
``.tables``
``.exit``
