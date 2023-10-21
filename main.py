from flask import Flask, jsonify, request
from flask_cors import CORS
import PyPDF2
from PyPDF2 import PdfReader
import os
from werkzeug.security import generate_password_hash, check_password_hash
import pickle


app = Flask(__name__)

with open(r"D:\QUANTIVE APP\backend\qna_model.pkl", "rb") as f:
    qna_model = pickle.load(f)

CORS(app)


users = {
    "user1": {"username": "user1", "password": generate_password_hash("password1")},
    "user2": {"username": "user2", "password": generate_password_hash("password2")}
}


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    user = users.get(username)
    if user and check_password_hash(user['password'], password):
        return jsonify({"message": "Login successful"})
    else:
        return jsonify({"error": "Invalid username or password"}), 401




@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'})

    file = request.files['file']

    if file.filename == '':
        return jsonify({'error': 'No selected file'})

    if file:
        metadata = pdf(file)
        global extracted_text 
        extracted_text = extract_text(file)
        
        return jsonify({'message': file.filename}, {'metadata' : metadata}, {'extract' : extracted_text})




@app.route('/qna', methods=['POST'])
def qna():
    data =  request.get_json()
    received_string =  data.get('data', '')
    # response_data = jsonify({'data': received_string})
    prediction = model(received_string, extracted_text)
    
    response_data1 = jsonify(prediction)

    return response_data1







def model(question, context):
    
    QA_input = {
        'question': question,
        'context': context
    }

    return qna_model(QA_input)

    

    
def pdf(file):
    if file:
        pdfReader = PyPDF2.PdfReader(file)
        metadata = pdfReader.metadata
        return metadata
    



    
def extract_text(file):
    if file:
        reader = PdfReader(file)    
        text = ''
        for i in reader.pages:
             text+=i.extract_text()

        return text





@app.route("/")
def homepage():
    return "Hello"



@app.route("/response", methods=['GET'])
def response():
    # a= "hello"
    return jsonify({"object": ["hello", "hii"]})

if __name__ == '__main__':
    app.run(debug=True)