from flask import *
import os

app = Flask(__name__)
UPLOAD_FOLDER = 'upload/'
if not os.path.isdir(UPLOAD_FOLDER):
    os.mkdir(UPLOAD_FOLDER)
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/')
def upload():
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
                return redirect(url_for('download_file', name=filename))
        return render_template("file_upload_form.html")
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
    #return render_template("success.html")

if __name__ == '__main__':
    app.run(debug = True)
