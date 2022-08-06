# Cloth-Detection
Using DeepLearning to perform cloth detection and distinction, with basic web UI.

# How to setup
- Make sure you have python3.9 installed.

- Install all the requirements
``python -m pip install requirements.txt`` for Windows or

  ``python3 -m pip install requirements.txt`` for Linux

- Download "yolo models" and save it as "yolo" in the the current working directory; link: [yolo](https://drive.google.com/drive/folders/1jXZZc5pp2OJCtmQYelzDgPzyuraAdxXP)

- Set up the database by running setup.py:

  ``python setup.py``

- Run the flask app:

  ``python flask_app.py``
