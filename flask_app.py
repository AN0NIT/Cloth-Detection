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

# For DL
import numpy as np
import torch
import os
import cv2
from yolo.utils.utils import *
from predictors.YOLOv3 import YOLOv3Predictor
import glob
from tqdm import tqdm
import sys


# Initialize flask app
app = Flask(__name__)
# Creates a database instance
db =  SQLAlchemy(app)
# Create an object for Bcrypt to hash the password
bcrypt = Bcrypt(app)
# Connect to DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
#app.config['SQLALCHEMY_DATABASE_URI'] = 'postgres://pqsgubluiyctxp:5b9b817c5c1302ab4c89396f3ec94a4754b4eee52918c278e9acb530ffdef8ee@ec2-34-236-88-129.compute-1.amazonaws.com:5432/d80j75mstf9gl3'
# To secure the session cookie.
# This key has to be set as environ variable, but for experimentation it is displayed in clear text
#app.config['SECRET_KEY'] = os.environ['SECRET_KEY']
app.config['SECRET_KEY'] = 'testingkeybutnotrealkey'
# It is set to True by default, set to False in real environment
#app.config['TESTING'] = False


UPLOAD_FOLDER = 'static/upload/'
ALLOWED_EXTENSIONS = ('png', 'jpg', 'jpeg')

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
def model_predict(img_path):
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    torch.cuda.empty_cache()
    yolo_modanet_params = {   "model_def" : "yolo/modanetcfg/yolov3-modanet.cfg",
    "weights_path" : "yolo/weights/yolov3-modanet_last.weights",
    "class_path":"yolo/modanetcfg/modanet.names",
    "conf_thres" : 0.5,
    "nms_thres" :0.4,
    "img_size" : 416,
    "device" : device}
    dataset = 'modanet'
    yolo_params = yolo_modanet_params
    #Classes
    classes = load_classes(yolo_params["class_path"])

    #Colors
    cmap = plt.get_cmap("rainbow")
    colors = np.array([cmap(i) for i in np.linspace(0, 1, 13)])
    detectron = YOLOv3Predictor(params=yolo_params)
    model = 'yolo'

    img_items = []
    path = img_path
    if not os.path.isfile(path):
        print('Img does not exists..')
        return "",[]

    img = cv2.imread(img_path)
    detections = detectron.get_detections(img)
    if len(detections) != 0 :
        detections.sort(reverse=False ,key = lambda x:x[4])
        for x1, y1, x2, y2, cls_conf, cls_pred in detections:
                if cls_conf < 0.8:
                    continue
                print("\t+ Label: %s, Conf: %.5f" % (classes[int(cls_pred)], cls_conf))
                img_items.append(classes[int(cls_pred)])
                #color = bbox_colors[np.where(unique_labels == cls_pred)[0]][0]
                color = colors[int(cls_pred)]

                color = tuple(c*255 for c in color)
                color = (.7*color[2],.7*color[1],.7*color[0])

                font = cv2.FONT_HERSHEY_SIMPLEX


                x1, y1, x2, y2 = int(x1), int(y1), int(x2), int(y2)
                text =  "%s conf: %.3f" % (classes[int(cls_pred)] ,cls_conf)

                cv2.rectangle(img,(x1,y1) , (x2,y2) , color,3)
                y1 = 0 if y1<0 else y1
                y1_rect = y1-25
                y1_text = y1-5

                if y1_rect<0:
                    y1_rect = y1+27
                    y1_text = y1+20
                cv2.rectangle(img,(x1-2,y1_rect) , (x1 + int(8.5*len(text)),y1) , color,-1)
                cv2.putText(img,text,(x1,y1_text), font, 0.5,(255,255,255),1,cv2.LINE_AA)
        #cv2.imshow('Detections',img)
        img_id = random.randint(100, 900)
        final_path = 'static/upload/ouput_test_{}_{}_{}.jpg'.format(img_id,model,dataset)
        print(final_path)
        print(os.path.join(os.getcwd(), final_path))
        if not cv2.imwrite(os.path.join(os.getcwd(), final_path),img):
            raise Exception(f"Could not write image {final_path}")
        cv2.imwrite(os.path.join(os.getcwd(), final_path),img)
        return final_path,img_items

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
            #salt = app.config['SECRET_KEY']
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
            elif f.filename.endswith(ALLOWED_EXTENSIONS):
                if not os.path.isdir(app.config['UPLOAD_FOLDER']):
                    os.mkdir(app.config['UPLOAD_FOLDER'])
                fname = os.path.join(app.config['UPLOAD_FOLDER'],f.filename)
                f.save(fname)
                try:
                    fpath,preds = model_predict(fname)
                except:
                    flash(f"No cloth found","error")
                    return redirect(url_for('dashboard'))
                fpath = fpath.split('static/upload/')[-1]
                print(fpath,preds)
                if preds == []:
                    flash(f"No cloth found","error")
                    return redirect(url_for('dashboard'))
                else:
                    items = ",".join( x for x in preds)
                    flash(f"Image contains {items}","success")
                return render_template("success.html", fname="upload/"+fpath)
            else:
                flash('Invalid file extention',"danger")
                return redirect(url_for('dashboard'))

@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static/images/'),'favicon.ico')


if __name__ == '__main__':
    app.run(debug=True)
