from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
from werkzeug.security import generate_password_hash, check_password_hash
import uuid
import jwt
import datetime
from functools import wraps

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = f"mysql+pymysql://merrette:pinch-wipe-pizza@api.merretech.io:3306/attack-sql"
app.config['SECRET_KEY'] = "C19PO-uzKGkiqX81Rs7VP3_epptOfuRj839SKZ7Lej-hQsa6"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
ma = Marshmallow(app)


class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50))
    name = db.Column(db.String(50))
    password = db.Column(db.String(150))
    admin = db.Column(db.Boolean)


class Detections(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    tactic = db.Column(db.String(100))
    technique = db.Column(db.String(100))
    sub_technique = db.Column(db.String(100))
    mitre_id = db.Column(db.String(10))

    def __init__(self, tactic, technique, sub_technique, mitre_id):
        self.tactic = tactic
        self.technique = technique
        self.sub_technique = sub_technique
        self.mitre_id = mitre_id


class DetectionsSchema(ma.Schema):
    class Meta:
        fields = ("id", "tactic", "technique", "sub_technique", "mitre_id")
        model = Detections


detection_schema = DetectionsSchema()
detections_schema = DetectionsSchema(many=True)


def token_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        token = None
        if 'x-access-tokens' in request.headers:
            token = request.headers['x-access-tokens']

        if not token:
            return jsonify({'message': 'a valid token is missing'}), 400
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = Users.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message': 'token is invalid'}), 401

        return f(current_user, *args, **kwargs)

    return decorator


@app.route('/register', methods=['GET', 'POST'])
def signup_user():
    user = request.json['name']
    password = request.json['password']

    hashed_password = generate_password_hash(password, method='sha256')

    new_user = Users(public_id=str(uuid.uuid4()), name=user, password=hashed_password, admin=False)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'registered successfully'})


@app.route('/login', methods=['POST'])
def login_user():
    auth = request.authorization
    if not auth or not auth.username or not auth.password:
        return make_response('could not verify', 401, {'Authentication': 'login required"'})

    user = Users.query.filter_by(name=auth.username).first()
    if check_password_hash(user.password, auth.password):
        token = jwt.encode(
            {'public_id': user.public_id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=45)},
            app.config['SECRET_KEY'], "HS256")

        return jsonify({'token': token}), 202

    return make_response('could not verify', 401, {'Authentication': '"login required"'})


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


@app.route('/')
def index():
    return jsonify({'message': 'see API documentation'})


@app.route('/attacks')
@token_required
def get(current_user):
    data = Detections.query.all()
    return jsonify({
        'detections': detections_schema.dump(data)
    }), 200


@app.route('/attacks/id/<id>')
@token_required
def get_id(current_user, id):
    data = Detections.query.filter(Detections.id == id)
    return jsonify({
        'detections': detections_schema.dump(data)
    })


@app.route('/attacks/mitre-id/<mitre_id>')
@token_required
def get_mitre(current_user, mitre_id):
    data = Detections.query.filter(Detections.mitre_id.like(f"%{mitre_id}%"))
    return jsonify({
        'detections': detections_schema.dump(data)
    })


@app.route('/attacks/create', methods=['POST'])
@token_required
def add_detection(current_user):
    tactic = request.json['tactic']
    technique = request.json['technique']
    sub_technique = request.json['sub_technique']
    mitre_id = request.json['mitre_id']

    if not any([tactic, technique, sub_technique, mitre_id]):
        return jsonify({'message': 'bad request'}), 400

    detection = Detections(tactic, technique, sub_technique, mitre_id)
    db.session.add(detection)
    db.session.commit()

    return detection_schema.jsonify(detection), 201


if __name__ == '__main__':
    app.run(host='0.0.0.0', port='5000')
