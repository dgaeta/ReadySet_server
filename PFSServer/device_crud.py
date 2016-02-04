import ast 
from PFSServer import storage
from gcloud import datastore
from passlib.apps import custom_app_context as pwd_context
from flask import Blueprint, current_app, redirect, render_template, request, \
    url_for, json, jsonify, g 
from flask.ext.httpauth import HTTPBasicAuth
from itsdangerous import (TimedJSONWebSignatureSerializer
                          as Serializer, BadSignature, SignatureExpired)


auth = HTTPBasicAuth()
# Copied from model_datastore.py
builtin_list = list # idk what this does 
device_crud = Blueprint('device_crud', __name__)


# START AUTH 
def hash_password(password):
	return pwd_context.encrypt(password)

def verify_password_helper(password_plain, password_hash):
	return pwd_context.verify(password_plain, password_hash)

@auth.verify_password
def verify_password(email_or_token, password):

  # first try to authenticate by token
  user = verify_auth_token(email_or_token)
  if not user:
    # try to authenticate with username/password

    ds = get_client()
    key = ds.key('User', str(email_or_token))
    results = ds.get(key)
    # End copy.

    # below was modified from: return from_datastore(results)
    user = from_datastore(results)

    if not user or not verify_password_helper(password, user['password']):
        return False
  g.user = user
  return True


def verify_auth_token(token):
  s = Serializer(current_app.config['SECRET_KEY'])
  try:
      data = s.loads(token)
  except SignatureExpired:
  	return None # valid token, but expired
  except BadSignature:
  	return None # invalid token

  ds = get_client()
  key = ds.key('User', str(data['email']))
  results = ds.get(key)
  # End copy.

  # below was modified from: return from_datastore(results)
  user = from_datastore(results)

  return user

# Copied from model_datastore.py
def get_client():
	return datastore.Client(dataset_id=current_app.config['DATASTORE_DATASET_ID'])

# Copied from model_datastore.py
# [START from_datastore]
def from_datastore(entity):
  """Translates Datastore results into the format expected by the
  application.

  Datastore typically returns:
      [Entity{key: (kind, id), prop: val, ...}]

  This returns:
      {id: id, prop: val, ...}
  """
  if not entity:
      return None
  if isinstance(entity, builtin_list):
      entity = entity.pop()

  entity['id'] = entity.key.id
  return entity
# [END from_datastore]


# Copied form model_datastore.py
def upsert(data, id=None):
  ds = get_client()
  if id:
  	key = ds.key('User', str(id))
  else:
  	key = ds.key('User', data['email'])

  entity = datastore.Entity(key=key)

  entity.update(data)
  ds.put(entity)
  return from_datastore(entity)


def device_upsert(data, id=None):
	ds = get_client()
	if id:
		key = ds.key('Device', id)
	else:
		key = ds.key('Device', data['id'])

	entity = datastore.Entity(key=key)

	entity.update(data)
	ds.put(entity)
 	return from_datastore(entity)

def remove_null(array):
	while True:
		try:
			array.remove('')
		except ValueError:
			break
	return array




@device_crud.route('/get_device')
@auth.login_required
def get_device(data = None, mode="production"):
	if data == None:
		data = request.json

	if mode == "testing":
		email = data['email']
   	else:
   		email = g.user['email']
   	
   	user = get_user(email)
   	device_id = data['device_id']
   	device_name = data['device_name']
 

   	if device_name in user['devices']:
   		device = get_device(device_id)

	    # Sanity check
	   	if device == None:
	   		return jsonify(status="failure", message="no device entity found with id: {}".format(device_id))
	   	else:
	   		return jsonify(status="success", device=device)
	else:
		return jsonify(status="failure", message="device id: {}, does not belong to user: {}".format(device_id, email))


@device_crud.route('/list_devices')
@auth.login_required
# PARAMS= None
# RETURNS= device_count: Int, devices: dict 
def list_devices(data = None, mode="production"):

	if mode == "testing":
		email = data['email']
   	else:
   		email = g.user['email']
   	
   	user = get_user(email)

   	if user != None:
   	    return jsonify( status="success", device_count=user['device_count'], devices=str(user['devices']))
   	else:
   	    return jsonify( status="failure", message="user not found")
    
 
@device_crud.route('/get_root')
@auth.login_required
# PARAMS= device_id, device_name
# RETURNS=  device_root: dict
def get_root(data= None, mode= "production"):
	if mode == "testing":
		email = data['email']
	else:
		data = request.json
		email = g.user['email']

	user = get_user(email)
	if user == None:
		return jsonify(status="failure", message="user with email: {}, not found".format(email))

	print data['device_id']
	if data['device_name'] in user['devices']:
		device = get_device(data['device_id'])

		if device != None:
			device_root = ast.literal_eval(device['children'])
			return jsonify(status="success", device_root= device_root)
		else:
			return jsonify(status="failure", message="device with id: {}, not found.")
	else:
		return jsonify(status="failure", message="device name: {}, not found in user: {}'s devices dict.".format(data['device_name'], email))

def get_device(device_id):
	ds = get_client()
	key = ds.key('Device', device_id)
 	results = ds.get(key)
 	device = from_datastore(results)
 	return device

def get_user(email):
	ds = get_client()
	key = ds.key('User', str(email))
	results = ds.get(key)
 	user = from_datastore(results)
 	user['devices'] = ast.literal_eval(user['devices'])
 	return user

@device_crud.route('/create_device')
@auth.login_required
def create_device():
  	data = request.json
  	email = g.user['email']
  	device_name = data['device_name']

  	ds = get_client()
    
	# Get the current user
  	user = get_user(email)

  	# Check if user exists
  	if user != None:
  		# Just in case 
	    if device_name in user['devices']:
	    	return jsonify(status='failure', message='device name already exists.')
	    else:

	    	# Create the Device root 'Folder' Entity
	    	key = ds.key('Device')
	    	entity = datastore.Entity(key=key)
	    	device = {'name': device_name, 'children': '{}', 'last_sync': 0}
	    	#device_string = str(device)
	    	#device_json = json.dumps(device)
	    	entity.update(device)
	    	ds.put(entity)

	    	result = from_datastore(entity)

	    	device["id"] = result["id"]
	    	device = device_upsert(device)

	    	user['device_count'] += 1
	    	user['devices'][device_name] = {'id': device['id'], 'name': device['name']}
	    	user['devices'] = str(user['devices'])
	    	user = upsert(user, email)
	    	return jsonify(status="success", email=user['email'], device_count=user['device_count'], devices=user['devices'], device_id=device['id'])
  	else:
  		return jsonify(status="failure", email=user['email'], message='no user found')



@device_crud.route('/delete_device')
@auth.login_required
def delete_device():
	data = request.json
 	email = g.user['email']
 	device_name = data['device_name']
 	device_id = data['device_id']

 	ds = get_client()
 	user = get_user(email)
 	device = get_device(device_id)

  	# Sanity check
 	if device == None:
 		return jsonify(status="failure", message="device entity not found")

	if device_name in user['devices']:
		del user['devices'][device_name]
		user['devices'] = str(user['devices'])
		upsert(user, email)
		key = ds.key('Device', device_id)
		ds.delete(key)
		return jsonify(status="success", message="Device id: {}, successfully deleted.".format(device_id))
	else:
		return jsonify(status="failure", message="Device name: {}, does not belong to user: {}".format(device_name, email))

# A node can be a folder or file 
@device_crud.route('/create_node')
@auth.login_required
def create_node():
  data = request.json
  email = g.user['email']
  path = data['path']
  mode = data['mode']
  node = data['node']
  device_id = data['device_id']


  ds = get_client()
  user = get_user(email)
  user['devices'] = ast.literal_eval(user['devices'])

  if user != None:

  	# Check if the device exists for this user
  	if device_unique_id not in user['devices']:
  		return jsonify(status='error, device_id not found')

  		# Get the device 
     	device = get_device(device_id)

     	# Sanity check
     	if device == None:
     		return jsonify(status="failure", message="device entity not found")
      
     	# Go to end of path 
     	node['children'] = {}
     	device['children'] = ast.literal_eval(device['children'])
     	curr_folder = device
     	if len(path) > 1: 
     		# Split the path string and create array 
     		path_array = path.split('/')
     		path_array = remove_null(path_array)

     		# recurse to the correct folder 
     		# Assumes device is not included in path 
       	for item in path_array:
       		curr_folder = curr_folder['children'][item]

     	
  	# Next, take the appropriate action
  	if mode == "Create":
  		curr_folder['children'][node['name']] = node

  		device['children'] = str(device['children'])
  		device = device_upsert(device, device['id'])
  		return jsonify(status="success", email=user['email'], current_folder=curr_folder)
  	else:
  		return jsonify(status="failure", message="node method not found.")
      
  else:
   	return jsonify(status="failure", email=user['email'], message='no user found')



def recurse_to_path(curr_folder, path):
	if len(path) > 1: 
		# Split the path string and create array 
		path_array = path.split('/')
		path_array = remove_null(path_array)

		# recurse to the correct folder 
		# Assumes device is not included in path 
		print path_array
		for item in path_array:
			if item in curr_folder['children']:
				curr_folder = curr_folder['children'][item]
			else:
				return "Error"
	return curr_folder

# A node can be a folder or file 
# PARAMS= path: string, device_id: int, device_name: String, path: String
# RETURNS= device_count: Int, devices: dict 
@device_crud.route('/list_children')
@auth.login_required
def list_children():
	data = request.json
 	email = g.user['email']
 	path = data['path']
 	device_id = data['device_id']

 	ds = get_client()
 	user = get_user(email)

 	if data['device_name'] not in user['devices']:
 		return jsonify(status="failure", message="device_name: {}, does not belong to user: {}".format(data['device_name'], email))
  # Get the device 
 	device = get_device(device_id)

  # Sanity check
 	if device == None:
 		return jsonify(status="failure", message="device entity not found")

 	# Recurse to path
 	device['children'] = ast.literal_eval(device['children'])
 	curr_folder = device
 	curr_folder = recurse_to_path(curr_folder, path)
 	if curr_folder == "Error":
 		return jsonify(status="failure", message="path {} not valid on device id: {}".format(path, device_id))
  
 	children = json.dumps(curr_folder['children'])
 	return jsonify(status="success", children=children)

# A node can be a folder or file 
@device_crud.route('/delete_node')
@auth.login_required
def delete_node():
	data = request.json
 	email = g.user['email']
 	node_name = data['node_name']
 	path = data['path']
 	device_id = data['device_id']

 	ds = get_client()
 	user = get_user(email)
 	device = get_device(device_id)

  # Sanity check
 	if device == None:
 		return jsonify(status="failure", message="device entity not found")

 	device['children'] = ast.literal_eval(device['children'])
 	curr_folder = device
 	curr_folder = recurse_to_path(curr_folder, path)
 	if curr_folder == "Error":
 		return jsonify(status="failure", message="path {} does not exist for device_id: {}".format(path, device_id))

 	if node_name in curr_folder['children']:
 		del curr_folder['children'][node_name]
 		device['children'] = str(device['children'])
 		device_upsert(device, device_id)
 		return jsonify(status="success", message="deleted node {}".format(node_name))
 	else:
 		return jsonify(status="failure", message="node does not exist at this path.")


#PARAMS: old_name: String, new_name: String, device_id: String, device_name: String
@device_crud.route('/rename_node')
@auth.login_required
def rename_node():
	data = request.json
 	email = g.user['email']
 	old_name = data['old_name']
 	new_name = data['new_name']
 	path = data['path']
 	device_id = data['device_id']


 	ds = get_client()
 	user = get_user(email)
 	device = get_device(device_id)

  # Sanity check
 	if device == None:
 		return jsonify(status="failure", message="device entity not found")

 	device['children'] = ast.literal_eval(device['children'])
 	curr_folder = device
 	curr_folder = recurse_to_path(curr_folder, path)
 	if curr_folder == "Error":
 		return jsonify(status="failure", message="path {} does not exist for device_id: {}".format(path, device_id))

 	if old_name in curr_folder['children']:
 		curr_folder['children'][new_name] = curr_folder['children'][old_name]
 		curr_folder['children'][new_name]['name'] = new_name
 		curr_folder['children'][new_name]['name'] = new_name
 		del curr_folder['children'][old_name]
 		device['children'] = str(device['children'])
 		device_upsert(device, device_id)
 		return jsonify(status="success", message="node renamed from {} to {}".format(old_name, new_name) )
 	else:
 		return jsonify(status="failure", message="node does not exist at this path.")


@device_crud.route('/create_symlink')
@auth.login_required
def create_symlink():
	data = request.json
 	email = g.user['email']
 	node_name = data['node_name']
 	path = data['path'] # this is the path of where the actual node exists
 	symlink_path = data['symlink_path'] # this is the path where the symlink will be created
 	symlink_name = data['symlink_name']
 	device_id = data['device_id']
 	device_name = data['device_name']


 	ds = get_client()
 	user = get_user(email)
 	device = get_device(device_id)

  # Sanity check
 	if device == None:
 		return jsonify(status="failure", message="device entity not found")

 	device['children'] = ast.literal_eval(device['children'])
 	curr_folder = device
 	curr_folder = recurse_to_path(curr_folder, path)
 	if curr_folder == "Error":
 		return jsonify(status="failure", message="path {} does not exist for device_id: {}".format(path, device_id))

 	if node_name in curr_folder['children']:
 		# Flag real node, that it has a symlink
 		curr_folder['children'][node_name]['symlink_exists'] = 1
 		curr_folder['children'][node_name]['symlink_path'] = symlink_path

 		# Flag the symlink as a symlink
 		symlink_folder = recurse_to_path(device, symlink_path)
 		if symlink_folder == "Error":
 			return jsonify(status="failure", message="path {} does not exist for device_id: {}".format(symlink_path, device_id))

 		symlink_folder['children'][symlink_name] = {'is_symlink': 1, 'actual_path': path, 'actual_name': node_name}
 		device['children'] = str(device['children'])
 		device_upsert(device)
 		return jsonify(status="success", message="symlink created from {} to {}".format(symlink_path, path))
 	else:
 		return jsonify(status="failure", message="path not valid")





@device_crud.route('/get_node')
@auth.login_required
def get_node():
	data = request.json
 	email = g.user['email']
 	node_name = data['node_name']
 	path = data['path'] # this is the path of where the actual node exists
 	device_id = data['device_id']
 	device_name =data['device_name']


 	ds = get_client()
 	user = get_user(email)
 	if data['device_name'] not in user['devices']:
 		return jsonify(status="failure", message="device_name: {}, does not belong to user: {}".format(data['device_name'], email))
 	device = get_device(device_id)

  # Sanity check
 	if device == None:
 		return jsonify(status="failure", message="device entity not found")

 	device['children'] = ast.literal_eval(device['children'])
 	curr_folder = device
 	curr_folder = recurse_to_path(curr_folder, path)
 	if curr_folder == "Error":
 		return jsonify(status="failure", message="path {} does not exist for device_id: {}".format(path, device_id))

 	if node_name in curr_folder['children']:
 		return jsonify(status="success", node=curr_folder['children'][node_name])
 	else:
 		return jsonify(status="failure", message="node does not exist at this path", path=path, node_name=node_name)

@device_crud.route('/edit_node')
@auth.login_required
def edit_node():
	data = request.json
 	email = g.user['email']
 	node_name = data['node_name']
 	path = data['path'] # this is the path of where the actual node exists
 	device_id = data['device_id']
 	prop_name = data['prop_name']
 	prop_value = data['prop_value']


 	ds = get_client()
 	user = get_user(email)
 	device = get_device(device_id)

  # Sanity check
 	if device == None:
 		return jsonify(status="failure", message="device entity not found")

 	device['children'] = ast.literal_eval(device['children'])
 	curr_folder = device
 	curr_folder = recurse_to_path(curr_folder, path)
 	if curr_folder == "Error":
 		return jsonify(status="failure", message="path {} does not exist for device_id: {}".format(path, device_id))

 	if node_name in curr_folder['children']:
 		curr_folder[children][node_name][prop_name] = prop_value
 		device['children'] = str(device['children'])
 		device_upsert(device)
 		return jsonify(status="success", message="node updated")
 	else:
 		return jsonify(status="failure", message="path not valid")


@device_crud.route('/sync')
@auth.login_required
def sync():
	data = request.json
 	email = g.user['email']
 	device_id = data['device_id']
 	commands_array = data['commands_array']
 	
 	ds = get_client()
 	user = get_user(email)
 	device = get_device(device_id)

  # Sanity check
 	if device == None:
 		return jsonify(status="failure", message="device entity not found")

 	device['children'] = ast.literal_eval(device['children'])
 	last_sync = device['last_sync']
 	
 	for command in commands_array:
 		c_id = command[0]
 		instr = command[3]

 		if c_id < last_sync:
 			pass

 		if c_id != last_sync + 1:
 			return jsonify(status="failure", message="batch mismatch. Current is {}, given {}".format(last_sync, c_id))

 		instr = ast.literal_eval(instr)
 		c_type = instr['type']

 		curr_folder = device
 		
 		path = instr['path']
 		path_array = path.split('/')
 		path_array = remove_null(path_array)

 		print(len(path_array))
	   	if len(path_array) > 1: 
	   		# recurse to the correct folder 
	   		# Assumes device is not included in path 
	   		for i in range(len(path_array)-1):
	   			if isinstance(curr_folder['children'], str):
	   				curr_folder['children'] = ast.literal_eval(curr_folder['children'])
	   			curr_folder = curr_folder['children'][path_array[i]]


	   	if isinstance(curr_folder['children'], str):
	   				curr_folder['children'] = ast.literal_eval(curr_folder['children'])
	 	if c_type == "create":
	 		curr_folder['children'][path_array[-1]] = {'name': path_array[-1], "is_file": 1, 'is_dir': 0,"mode": instr['mode'], 'inserted_id': instr['inserted_id'], 'children': '{}'}


	  	elif c_type == "utimens":
	  		curr_folder['children'][path_array[-1]]["m_time"] = instr["m_time"]
	  		curr_folder['children'][path_array[-1]]["a_time"] = instr["a_time"]


	  	elif c_type == "chmod":
	  		curr_folder['children'][path_array[-1]]["mode"] = instr['mode']
	  		
	  	elif c_type == "rmdir":
	  		del curr_folder['children'][path_array[-1]]
	  		
		elif c_type == "rename":
			curr_folder['children'][new_name] = curr_folder['children'][old_name]
			curr_folder['children'][new_name]['name'] = new_name
			curr_folder['children'][new_name]['name'] = new_name
			del curr_folder['children'][old_name]

		elif c_type == "unlink":		
			del curr_folder['children'][node_name]
			print "deleted node {}".format(node_name)

	  	elif c_type == "mkdir":
	   		curr_folder['children'][path_array[-1]] = {'name': path_array[-1], "is_file": 0, 'is_dir': 1,"mode": instr['mode'], 'children': '{}'}

	  	elif c_type == "symlink":
			target_path = instr['target'] # this is the path where the symlink will be created

	   		curr_folder['children'][path_array[-1]] = {'name': path_array[-1], 'target_path': target_path, "is_symlink": 1,"is_file": 0, 'is_dir': 0}
			# print("symlink created from {} to {}".format(symlink_path, path

		last_sync = c_id
		device['last_sync'] = last_sync
		device['children'] = str(device['children'])
		device_upsert(device, device_id)

	return jsonify(status="success", last_sync=last_sync)