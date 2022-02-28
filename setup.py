from flask_app import db
import os




def main():
    if not os.path.isfile("database.db"):
        f = open('database.db','w')
        f.close()
    db.create_all()

if __name__ == "__main__":
    main()
