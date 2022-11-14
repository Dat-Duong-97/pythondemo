import jwt
from functools import wraps
from flask import Blueprint, request, jsonify, make_response
from flask import current_app as app
from model import Token, User

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        
        if not token:
            return jsonify({'message':'Token is missing'}), 401

        #Check the token is in black list table or not
        # token_invalid = Token.objects(token=token).first()
        # if token_invalid is not None:
        #     return jsonify({'message':'Token is out of date'}), 401

        try:
            #encode token with sha256 algorithm and secret key
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = User.objects(id = data['public_id']).first()
        except:
            return jsonify({'message' : 'Token is invalid'}), 401
        return f(current_user, token ,*args, **kwargs)
    return decorated