from app.flask_app import app
from app.flask_app import db

if __name__ == "__main__":
    db.create_all()
    app.run()
