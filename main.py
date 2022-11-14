from weakref import ReferenceType
from flask import Flask,request, jsonify, make_response
from pymongo import MongoClient
from mongoengine import connect, disconnect, DynamicDocument, IntField, StringField, ReferenceField
import hashlib
from simpleflake import simpleflake
from bson.json_util import dumps
import json
from wraps import token_required
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from model import User, Token
import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = '14320edb76fb8c6018c28b07'
connect(db="mydatabase", host='mongodb+srv://dat:duongtuandat123@cluster0.vqmrfwo.mongodb.net/?retryWrites=true&w=majority')


#Register account
@app.route('/register', methods=['POST'])
def create_user():
    data = request.get_json(force = False, silent = False, cache = True)
    if(data['name'] == ""):
        return jsonify({'message':'username is invalid'}), 401
    if(data['email'] == ""):
        return jsonify({"message": "email is invalid"}), 401
    if ' ' in data['email'] :
        return jsonify({'message':'email is invalid'}), 401
    if(data['password'] == ""):
        return jsonify({"message":"password is invalid"}), 401
    
    data['password'] = generate_password_hash(data['password'], 'sha256')

    try:
        new_user = User(email = data['email'], name = data['name'], age = data['age'], password = data['password'])
        new_user.save()
    except:
        return jsonify({'message' : 'This email is already taken'})

    return jsonify({'message':"success"}), 200

#Login Account
@app.route("/login", methods=["GET"])
def login():
    auth = request.authorization
    if not auth or not auth.username or not auth.password:
        return make_response('Empty space', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})
    
    user = User.objects(email = auth.username).first()

    if not user:
        return make_response('User not found', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

    if check_password_hash(user.password, auth.password):
        #Duration 2000 mins
        token = jwt.encode({'public_id': user.id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=2000)}, app.config['SECRET_KEY'])
        tokenDB = Token(userId = user.id, token = token)
        tokenDB.save()
        user.token.append(tokenDB)
        user.save()
        return jsonify({'token' : token})

    return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})


@app.route("/get_user", methods=["GET"])
@token_required
def getUser(current_user, token):
    id = current_user.id
    user = User.objects(id = id).first()
    if not user:
        return jsonify({'message' : 'No user found!'})
    user_data = {}
    user_data['email'] = user.email
    user_data['name'] = user.name
    user_data['age'] = user.age
    user_data['token'] = []
    print(type(user_data['token']))
    for i in user.token:
        user_data['token'].append(i.token)
    return jsonify({'user': user_data})


@app.route("/change_password", methods=["PUT"])
@token_required
def changePassword(current_user, token):
    data = request.get_json()
    userId = current_user.id
    user = User.objects(id = userId).first()
    if not user:
        return jsonify({'message' : 'No user found!'})
    
    if check_password_hash(user.password, data['old_password']):
        if data.get('new_password'):
            user.update(password = generate_password_hash(data['new_password'], 'sha256'))
            user.reload()
            return jsonify({'message' : 'Password has changed'})
    return jsonify({'message' : 'Change password failed'})

@app.route("/change_name", methods=["PUT"])
@token_required
def changename(current_user, token):
    data = request.get_json()
    userId = current_user.id
    user = User.objects(id = userId).first()
    if not user:
        return jsonify({'message': "No user found!"})
    
    if data.get('new_name'):
        user.update(name = data['new_name'])
        user.reload()
        return jsonify({'message':'Name has changed'})
    return jsonify({'message':'Change name failed'})


if __name__ == '__main__':
    app.run(debug=True)