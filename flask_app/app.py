import uuid
import datetime
import os
import re
import pymongo
import jwt

from flask import Flask, request, jsonify, make_response
from passlib.hash import pbkdf2_sha256
from dotenv import load_dotenv
from functools import wraps



# Development Tools
load_dotenv()

# Flask App
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv("JWT_SECRET_KEY")

# Database
client = pymongo.MongoClient('localhost', 27017)
db = client.users

def token_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        token = None
        if 'x-access-tokens' in request.headers:
            token = request.headers['x-access-tokens']

        if not token:
            return jsonify({'message': 'a valid token is missing'}), 403
        
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = db.users.find_one({"_id": data["public_id"]})
        except:
            return jsonify({'message': 'token is invalid'}), 401

        return f(current_user, *args, **kwargs)

    return decorator


@app.route('/register', methods=['POST'])
def signup_user():

    name = request.json['name']
    username = request.json['username']
    password = request.json['password']

    hashed_password = pbkdf2_sha256.encrypt(password)
    user = {
        "_id": uuid.uuid4().hex,
        "name": name,
        "username": username,
        "password": hashed_password
    }

    if db.users.find_one({"username": username}):
        return jsonify({'error': 'user already exists'}), 400
 
    if db.users.insert_one(user):
        return jsonify({'message': 'registered successfully'}), 200


@app.route('/login', methods=['POST'])
def login_user():
    auth = request.authorization
    if not auth or not auth.username or not auth.password:
        return make_response('could not verify', 401, {'Authentication': 'login required'})

    user = db.users.find_one({"username": auth.username})

    if pbkdf2_sha256.verify(auth.password, user['password']):
        token = jwt.encode(
            {'public_id': user["_id"], 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=45)},
            app.config['SECRET_KEY'], "HS256")

        return jsonify({'token': token}), 202

    return make_response('could not verify', 401, {'Authentication': 'login required'})


@app.route('/')
def index():
    return jsonify({'message': 'see API documentation'})


@app.route('/users', methods=['GET'])
@token_required
def get_all_users(current_user): 
    collection = db['users']
    results = []

    for user in collection.find():
        results.append(user)

    return jsonify({'users': results})


@app.route('/attacks', methods=['GET'])
@token_required
def get(current_user):

    collection = db['detections']
    results = []

    for detection in collection.find():
        results.append(detection)

    return jsonify({'detections': results})



@app.route('/attacks/id/<id>', methods=['GET'])
@token_required
def get_id(current_user, id):

    # input validation
    regex_exp = re.compile(r'^(MA|TA|T|M|G|S)\d{4}(.\d{3})?$')
    if not regex_exp.search(id):
        return jsonify({"error": "input value for id is not valid"}), 400

    results = []
    collection = db['detections']
    mitre_id = collection.find({"mitre_data.mitre_id": {'$regex': id}})

    try:
        mitre_id[0]
    except IndexError:
        return jsonify({"message": "no detections found for the provided id"})

    for rule in mitre_id:
        if id in rule["mitre_data"]["mitre_id"]:
            results.append(rule)
            return jsonify({'detections': results})


@app.route('/attacks/create', methods=['POST'])
@token_required
def add_detection(current_user):

    collection = db['detections']

    new_detection = request.json
    new_detection["_id"] = uuid.uuid4().hex

    new_rule = new_detection["detection"]["rule"]
    current_rule = collection.find_one({"detection.rule": new_rule})

    if new_rule == current_rule["detection"]["rule"]:
        return jsonify({
            "error": {
                "message": "detection already exists, see _id",
                "_id": current_rule["_id"]
            }
            }), 400

    collection.insert_one(new_detection)

    return jsonify({'created': new_detection}), 200


@app.route('/attacks/delete', methods=['DELETE'])
@token_required
def delete_detection(current_user):
    return jsonify({
        'message': "this endpoint is yet to be created"
    })


@app.route('/attacks/update', methods=['PUT'])
@token_required
def update_detection(current_user):
    return jsonify({
        'message': "this endpoint is yet to be created"
    })


if __name__ == '__main__':
    app.run(host='0.0.0.0', port='5000')
