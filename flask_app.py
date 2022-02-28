from flask import Flask, render_template, url_for, redirect, request, flash, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
import os
import time
import random
# For the DL
import numpy as np
from image2mnist import imageprepare   #To convert image to mnist data
from tensorflow.keras.models import load_model
from tensorflow.keras.preprocessing import image
from keras.applications.imagenet_utils import preprocess_input

# Initialize flask app
app = Flask(__name__)
# Creates a database instance
db =  SQLAlchemy(app)
# Create an object for Bcrypt to hash the password
bcrypt = Bcrypt(app)
# Connect to DB
#app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgres://pqsgubluiyctxp:5b9b817c5c1302ab4c89396f3ec94a4754b4eee52918c278e9acb530ffdef8ee@ec2-34-236-88-129.compute-1.amazonaws.com:5432/d80j75mstf9gl3'
# To secure the session cookie.
# This key has to be set as environ variable, but for experimentation it is displayed in clear text
#app.config['SECRET_KEY'] = os.environ['SECRET_KEY']
app.config['SECRET_KEY'] = 'testingkeybutnotrealkey'
# It is set to True by default, set to False in real environment
#app.config['TESTING'] = False


UPLOAD_FOLDER = 'static/upload/'
ALLOWED_EXTENSIONS = ('png', 'jpg', 'jpeg')
MODEL_NAME = "model/my_model2.h5"
model = load_model(MODEL_NAME)
model.make_predict_function()

if not os.path.isdir(UPLOAD_FOLDER):
    os.mkdir(UPLOAD_FOLDER)



app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# To Initialize a database with the columns id, username and password
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True,nullable=False)
    password = db.Column(db.String(80), nullable=False)

# Passes the model and the image to be predicted.
def model_predict(img_path, model):
    first_image = np.array(imageprepare(img_path), dtype='float32')
    first_image = first_image.reshape((28,28))
    predictions = model.predict(np.expand_dims(first_image,0))
    out = np.argmax(predictions)
    class_labels = ["T-shirt","Trouser","Pullover","Dress","Coat","Footwear","Shirt","Footwear","Bag","Footwear"]
    return class_labels[out]


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def home():
    return redirect(url_for('login'))


@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        USRN = request.form['username']
        PASSW = request.form['password']
        if PASSW == '':
            flash("Incorrect username or password!","danger")
            return render_template("login.html")
        user = User.query.filter_by(username=USRN).first()
        if user:
            if bcrypt.check_password_hash(user.password, PASSW):
                login_user(user)
                return redirect(url_for('dashboard'))
            else:
                flash("Incorrect username or password!","danger")
                return render_template("login.html")
        else:
            flash("Incorrect username or password!","danger")
            return render_template("login.html")
    else:
        return render_template("login.html")


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("You are now logged out.", "info")
    return redirect(url_for('login'))

@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        USRN = request.form['username']
        PASSW = request.form['password']
        REPASS = request.form['repassword']
        if USRN == '':
            flash("Please enter an email.","warning")
            return render_template("register.html")
        if PASSW == '' or REPASS == '':
            flash("Please enter the password","warning")
            return render_template("register.html")
        if REPASS == PASSW:
            salt = app.config['SECRET_KEY']
            hashed_password = bcrypt.generate_password_hash(PASSW)
            #hashed_password = bcrypt.hashpw(PASSW, salt)
            new_user = User(username=USRN, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            flash("Account created succesfully.","success")
            return redirect(url_for('login'))
        else:
            #raise ValidationError("Passwords dont match.")
            flash("Passwords dont match.","danger")
            return render_template("register.html")
    else:
        return render_template("register.html")

@app.route('/dashboard', methods=['GET','POST'])
@login_required
def dashboard():
    try:
        if request.method == 'POST':
            # check if the post request has the file part
            if 'file' not in request.files:
                flash('No file part')
                return redirect(request.url)
            file = request.files['file']
            # If the user does not select a file, the browser submits an
            # empty file without a filename.
            if file.filename == '' or file.filename is None:
                flash('No selected file',"warning")
                return redirect(request.url)
            print('{file} and {allowed_file(file.filename)}')
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                return redirect(url_for('success', name=filename))
            else:
                flash("File type not allowed.","danger")
                return redirect(request.url)
        return render_template("dashboard.html")
    except PermissionError as e:
        return redirect(request.url)

@app.route('/success', methods = ['GET','POST'])
def success():
    cloths = ["shirt","hoodie","tshirt","suit"]
    type = random.choice(cloths)
    if request.method == 'POST':
        try:
            feedback = request.form['feedback']
            if feedback != '' or feedback is not None:
                # here the feedback variable can be stored to a csv file or for storing feedback's from users
                flash("Thank you for your valuable feedback.","success")
                return redirect(url_for('dashboard'))
        except:
            f = request.files['file']
            if f.filename is None or f.filename == '':
                flash('No selected file',"warning")
                return redirect(url_for('dashboard'))
                #return redirect('/')
            elif f.filename.endswith(ALLOWED_EXTENSIONS):
                if not os.path.isdir(app.config['UPLOAD_FOLDER']):
                    os.mkdir(app.config['UPLOAD_FOLDER'])
                fname = os.path.join(app.config['UPLOAD_FOLDER'],f.filename)
                f.save(fname)
                preds = model_predict(fname,model)
                if preds.lower() == "no cloth found.":
                    flash(f"{preds}","error")
                else:
                    flash(f"It is a {preds}","success")
                return render_template("success.html", fname='upload/'+f.filename)
            else:
                flash('Invalid file extention',"danger")
                return redirect(url_for('dashboard'))

@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static/images/'),'favicon.ico')


if __name__ == '__main__':
    app.run(debug=True)
