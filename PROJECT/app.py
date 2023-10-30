from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import uuid
import jwt
import datetime
from functools import wraps
import imghdr
import os
import urllib.request
from werkzeug.utils import secure_filename

app = Flask(__name__)
UPLOAD_FOLDER = 'uploads'
app.config['SECRET_KEY']='004f2af45d3a4e161a7dd2d17fdae47f'
app.config['SQLALCHEMY_DATABASE_URI']='sqlite:///books.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
app.config['MAX_CONTENT_LENGTH'] = 1024 * 1024
app.config['UPLOAD_EXTENSIONS'] = ['.jpg', '.png', '.gif']
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

@app.errorhandler(400)
def bad_request(e):
    return jsonify(error=str(e), code=400, message="Bad Request"), 400

@app.errorhandler(401)
def unauthorized(e):
    return jsonify(error=str(e), code=401, message="Unauthorized"), 401

@app.errorhandler(404)
def not_found(e):
    return jsonify(error=str(e), code=404, message="Resource Not Found"), 404

@app.errorhandler(500)
def internal_server_error(e):
    return jsonify(error=str(e), code=500, message="Internal Server Error"), 500


db = SQLAlchemy(app)

class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.Integer)
    name = db.Column(db.String(50))
    password = db.Column(db.String(50))
    admin = db.Column(db.Boolean)

with app.app_context():
    db.create_all()

class Books(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    name = db.Column(db.String(50), unique=True, nullable=False)
    Author = db.Column(db.String(50), unique=True, nullable=False)
    Publisher = db.Column(db.String(50), nullable=False)
    book_prize = db.Column(db.Integer)
with app.app_context():
    db.create_all()

def token_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):

        token = None

        if 'x-access-tokens' in request.headers:
            token = request.headers['x-access-tokens']

        if not token:
            return jsonify({'message': 'a valid token is missing'})
        
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = Users.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message': 'token is invalid'})

        return f(current_user, *args, **kwargs)
    return decorator


@app.route('/register', methods=['POST'])
def signup_user():  
    data = request.get_json()  

    hashed_password = generate_password_hash(data['password'], method='pbkdf2')
 
    new_user = Users(public_id=str(uuid.uuid4()), name=data['name'], password=hashed_password, admin=False) 
    db.session.add(new_user)  
    db.session.commit()    

    return jsonify({'message': 'registeration successfully'})

@app.route('/login', methods=['POST'])  
def login_user(): 
    auth = request.authorization   

    if not auth or not auth.username or not auth.password:  
        return make_response('could not verify', 401, {'Authentication': 'login required"'})    

    user = Users.query.filter_by(name=auth.username).first()   
     
    if check_password_hash(user.password, auth.password):

        token = jwt.encode({'public_id' : user.public_id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=45)}, app.config['SECRET_KEY'], "HS256").decode('utf-8')
        return jsonify({'token' : token}) 

    return make_response('could not verify',  401, {'Authentication': '"login required"'})

@app.route('/users', methods=['GET'])
def get_all_users():  
   
    users = Users.query.all() 
    result = []   
    for user in users:   
        user_data = {}   
        user_data['public_id'] = user.public_id  
        user_data['name'] = user.name 
        user_data['password'] = user.password
        user_data['admin'] = user.admin 
       
        result.append(user_data)   

    return jsonify({'users': result})

@app.route('/book', methods=['POST'])
@token_required
def create_book(current_user):
   
    data = request.get_json() 

    new_books = Books(name=data['name'], Author=data['Author'], Publisher=data['Publisher'], book_prize=data['book_prize'], user_id=current_user.id)  
    db.session.add(new_books)   
    db.session.commit()   

    return jsonify({'message' : 'new books created'})


@app.route('/books', methods=['GET'])
@token_required
def get_books(current_user):

    books = Books.query.filter_by(user_id=current_user.id).all()

    output = []
    for book in books:
        book_data = {}
        book_data['id'] = book.id
        book_data['name'] = book.name
        book_data['Author'] = book.Author
        book_data['Publisher'] = book.Publisher
        book_data['book_prize'] = book.book_prize
        output.append(book_data)

    return jsonify({'list_of_books' : output})

@app.route('/books/<book_id>', methods=['DELETE'])
@token_required
def delete_book(current_user, book_id):  
    book = Books.query.filter_by(id=book_id, user_id=current_user.id).first()   
    if not book:   
        return jsonify({'message': 'book does not exist'})   

    db.session.delete(book)  
    db.session.commit()   

    return jsonify({'message': 'Book deleted'})

ALLOWED_EXTENSIONS = set(['txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'])

def allowed_file(filenmae):
    return '.'  in filenmae and filenmae.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/upload', methods=['POST'])
def upload_files():
    if 'files[]' not in request.files:
        resp = jsonify({'message' : 'No file part in the request'})
        resp.status_code = 400
        return resp
    files = request.files.getlist('files[]')
    errors = {}
    success = False
    for file in files:
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            success = True
        else:
            errors[file.filename] = 'File type is not allowed'
    
    if success and errors:
        errors['message'] = 'File(s) successfully uploaded'
        resp = jsonify(errors)
        resp.status_code = 500
        return resp
    
    if success:
        resp = jsonify({'message' : 'Files successfully uploaded'})
        resp.status_code = 201
        return resp
    else:
        resp = jsonify(errors)
        resp.status_code = 500
        return resp
    

@app.route('/')
def home():
 
    
    return jsonify({
        'name': 'The C++ programming Language, 4th Edition',
        'Author': 'Bjarne Stroustrup',
        'Publisher': '',
        'book_prize': '63.99'
    })


if  __name__ == '__main__':  
     app.run(debug=True)