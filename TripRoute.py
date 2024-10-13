from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required
from pymongo import MongoClient
import bcrypt

# Crear la aplicación Flask
app = Flask(__name__)

# Configuración de clave secreta para JWT
app.config['JWT_SECRET_KEY'] = 'clave_super_secreta'  # Cambiar por una clave más segura en producción
jwt = JWTManager(app)

# Conectar a MongoDB
client = MongoClient('mongodb://localhost:27017/')
db = client['triproute_db']  # Base de datos para la aplicación
users_collection = db['users']
routes_collection = db['routes']

# Función para registrar un nuevo usuario
@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data['username']
    password = data['password']
    
    # Verificar si el usuario ya existe
    if users_collection.find_one({'username': username}):
        return jsonify({'message': 'Usuario ya registrado'}), 400
    
    # Encriptar contraseña
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    
    # Guardar nuevo usuario en la base de datos
    users_collection.insert_one({'username': username, 'password': hashed_password})
    return jsonify({'message': 'Usuario registrado exitosamente'}), 201

# Función para inicio de sesión
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data['username']
    password = data['password']
    
    # Verificar si el usuario existe
    user = users_collection.find_one({'username': username})
    if not user or not bcrypt.checkpw(password.encode('utf-8'), user['password']):
        return jsonify({'message': 'Credenciales incorrectas'}), 401
    
    # Crear token JWT
    access_token = create_access_token(identity=username)
    return jsonify({'access_token': access_token}), 200

# Función para crear una nueva ruta de viaje
@app.route('/create_route', methods=['POST'])
@jwt_required()
def create_route():
    data = request.json
    username = data['username']  # Se obtiene del token, en la realidad
    route_name = data['route_name']
    destinations = data['destinations']  # Lista de destinos
    
    # Guardar la nueva ruta
    routes_collection.insert_one({
        'username': username,
        'route_name': route_name,
        'destinations': destinations
    })
    return jsonify({'message': 'Ruta creada exitosamente'}), 201

# Función para consultar rutas guardadas
@app.route('/get_routes', methods=['GET'])
@jwt_required()
def get_routes():
    username = request.args.get('username')  # En una implementación real, el nombre de usuario vendría del token
    
    # Consultar rutas del usuario
    routes = list(routes_collection.find({'username': username}, {'_id': 0}))
    
    if routes:
        return jsonify({'routes': routes}), 200
    else:
        return jsonify({'message': 'No se encontraron rutas'}), 404

# Iniciar la aplicación
if __name__ == '__main__':
    app.run(debug=True)

