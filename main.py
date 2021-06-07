from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy 
from functools import wraps
import datetime
import jwt

app = Flask(__name__)
app.config['SECRET_KEY'] 						= 'myKey'
app.config['SQLALCHEMY_DATABASE_URI'] 			= 'postgresql://postgres:admin16@localhost:5432/tp_obj'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] 	= True

db = SQLAlchemy(app)

class Product(db.Model):
	__tablename__ = 'products'
	id 			= db.Column(db.Integer, primary_key=True)
	product 	= db.Column(db.String)
	cash		= db.Column(db.Integer)

class Inventory(db.Model):
	__tablename__ = 'inventory'
	id_user		= db.Column(db.Integer, primary_key=True)
	id_product	= db.Column(db.Integer, primary_key=True)
	stock 		= db.Column(db.Integer)

class User(db.Model):
	__tablename__ = 'users'
	id 			= db.Column(db.Integer, primary_key=True)
	email		= db.Column(db.String)
	pass_hash 	= db.Column(db.String)
	name		= db.Column(db.String)
	surname		= db.Column(db.String)
	cash		= db.Column(db.Integer)

def token_verify(f):
	@wraps(f)
	def decorated(*args, **kwargs):
		token = None

		if 'x-access-token' in request.headers:
			token = request.headers['x-access-token']
		if not token:
			return jsonify({'code': 401, 'message': 'Token missing'})
		try:
			data = jwt.decode(token, app.config['SECRET_KEY'])
			current_user = User.query.filter_by(id=data['id']).first()
		except:
			return jsonify({'code': 401, 'message': 'Token invalid'})

		return f(current_user, *args, **kwargs)
	return decorated

def query_user(user_id):
	return User.query.filter_by(id=user_id).first()

@app.route('/register', methods=['POST'])
def put_user():
	data = request.get_json()
	hash_pwd = generate_password_hash(data['password'], method='sha256')
	new_user = User(email=data['email'], name=data['name'], surname=data['surname'], pass_hash=hash_pwd, cash=0)
	db.session.add(new_user)
	db.session.commit()
	return jsonify({'code': 200, 'message': 'User Created'})

@app.route('/login', methods=['POST'])
def get_token():
	data = request.get_json()

	if not data or not data['email'] or not data['password']:
		return make_response('Could not verify', 401)

	user = User.query.filter_by(email=data['email']).first()
	if not user:
		return jsonify({'code': 404, 'message': 'No user found'})

	if check_password_hash(user.pass_hash, data['password']):
		token = jwt.encode({
			'id': 	user.id, 
			'exp': 	datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
			}, 
			app.config['SECRET_KEY']
		)
		return jsonify({'code': 200, 'token': token.decode('UTF-8')})
	return make_response('Could not verify', 401)

@app.route('/profile', methods=['GET'])
@token_verify
def get_profile(current_user):
	user 	= query_user(current_user.id)
	data 	= {
		"email":	user.email,
		"name":		user.name,
		"surname":	user.surname,
		"cash":		user.cash
	}
	return jsonify({'code': 200, 'data': data})

@app.route('/inventory', methods=['GET'])
@token_verify
def get_inventory(current_user):
	productList = Inventory.query.filter_by(id_user=current_user.id).all()
	productJson = []
	for product in productList:
		prd = Product.query.filter_by(id=product.id_user).first()
		productBuf = {
			"product":	prd.product,
			"stock":	product.stock
		}
		productJson.append(productBuf)
	return jsonify({'code': 200, 'data': productJson})

@app.route('/shop', methods=['POST'])
@token_verify
def put_compras(current_user):
	data = request.get_json()
	usrProfile = query_user(current_user.id)

	# Calcular Costo de compra
	totalCost = 0
	for row in data['cart']:
		prd = Product.query.filter_by(id=row['id_product']).first()
		if prd is None:
			# Corte si no encuentra producto
			return jsonify({'code': 404, 'message': 'Item not found'})
		totalCost += prd.cash * row['stock']

	if usrProfile.cash >= totalCost:
		for row in data['cart']:
			# Buscar si existe item en tabla de inventario
			currentItem 	= Inventory.query.filter_by(id_user=current_user.id, id_product=row['id_product']).first()
			if currentItem is None:
				# Insertar item nuevo si no existe
				new_item 	= Inventory(id_user=current_user.id, id_product=row['id_product'], stock=row['stock'])
				db.session.add(new_item)
			else:
				# Actualizar stock de item si existe
				currentItem.stock += row['stock']
		# Actualizar plata de usuario
		usrProfile.cash -= totalCost
		db.session.commit()
		return jsonify({'code': 200, 'message': 'Products Created'})
	else:
		return jsonify({'code': 401, 'message': 'No cash'})

@app.route('/products', methods=['GET'])
@token_verify
def get_products(current_user):
	productList = Product.query.all()
	productJson = []
	for product in productList:
		productBuf = {
			"id":		product.id,
			"product":	product.product,
			"cash":		product.cash
		}
		productJson.append(productBuf)
	return jsonify({'code': 200, 'data': productJson})

if __name__ == '__main__':
	app.run(debug=True)