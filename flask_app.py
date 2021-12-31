from flask import Flask, render_template, url_for, redirect, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
import os

# Initialize flask app
app = Flask(__name__)
# Creates a database instance
db =  SQLAlchemy(app)
# Create an object for Bcrypt to hash the password
bcrypt = Bcrypt(app)
# Connect to DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
# To secure the session cookie.
# This key has to be set as environ variable, but for experimentation it is displayed in clear text
#app.config['SECRET_KEY'] = os.environ['SECRET_KEY']
app.config['SECRET_KEY'] = 'testingkeybutnotrealkey'

UPLOAD_FOLDER = 'upload/'
if not os.path.isdir(UPLOAD_FOLDER):
    os.mkdir(UPLOAD_FOLDER)
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
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

# To create a registration form
class RegistrationForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder":"Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder":"Password"})
    #re_password = PasswordField(validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder":"Re-Enter Password"})
    submit = SubmitField("Register")
    """
    def validate_passwords(self, password, re_password):
        if password != re_password:
            raise ValidationError("Passwords dont match.")
    """
    def validate_user(self, username):
        existing_user_username = User.query.filter_by(username=username.data).first()
        if existing_user_username:
            raise ValidationError("Username Already Exists, try a different username.")


# To create Login Form
class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder":"Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder":"Password"})
    submit = SubmitField("Login")

@app.route('/')
def home():
    return render_template("home.html")


@app.route('/login', methods=['GET','POST'])
def login():
    #form = LoginForm()
    #if form.validate_on_submit():
    if request.method == 'POST':
        USRN = request.form['username']
        PASSW = request.form['password']
        user = User.query.filter_by(username=USRN).first()
        if user:
            if bcrypt.check_password_hash(user.password, PASSW):
                login_user(user)
                return redirect(url_for('dashboard'))
    else:
        return render_template("login.html")

@app.route('/logout', methods=['GET','POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/register', methods=['GET','POST'])
def register():
    #form = RegistrationForm()
    #if form.validate_on_submit():
    if request.method == 'POST':
        USRN = request.form['username']
        PASSW = request.form['password']
        REPASS = request.form['repassword']
        if REPASS == PASSW:
            hashed_password = bcrypt.generate_password_hash(PASSW)
            new_user = User(username=USRN, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for('login'))
        else:
            #raise ValidationError("Passwords dont match.")
            flash("Passwords dont match.")
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
                flash('No selected file')
                return redirect(request.url)
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                #flash("fname:",filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                #flash(file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename)))
                return redirect(url_for('success.html', name=filename))
        return render_template("dashboard.html")
    except PermissionError as e:
        return redirect(request.url)

@app.route('/success', methods = ['POST'])
def success():
    if request.method == 'POST':
        f = request.files['file']
        if f.filename is None or f.filename == '':
            return redirect(request.url)
            #return redirect('/')
        f.save(os.path.join(app.config['UPLOAD_FOLDER'],f.filename))
        return render_template("success.html", name=f.filename)

if __name__ == '__main__':
    app.run(debug=True)
