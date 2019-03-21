#imports what is needed to run the application as an instance of the Flask Object and handle json requests
from flask import Flask, jsonify, request
#imports what is needed to run application as an API
from flask_restful import Api, Resource
#imports mongodb and its python client
from pymongo import MongoClient
#imports bcrypt to handle the hashing of passwords
import bcrypt
#imports the spacy module
import spacy

#define the app and instantiates it as an API
app = Flask(__name__)
api = Api(app)

#starts database and create collection
client = MongoClient("mongodb://db:27017")
db = client.SimilarityDB2
users = db["Users"]

#function that verify if the password entered by the user match the hashed pw in the db
def verifyPw(username, password):
    if not UserExist(username):
        return False

    #uses the username to find its matching password
    hashed_pw = users.find({
        "Username": username
    })[0]["Password"]

    # returns True if password enteres matches its hashed version, else returns False
    if bcrypt.hashpw(password.encode('utf8'), hashed_pw) == hashed_pw:
        return True
    else:
        return False

def UserExist(username):
    if users.find({"Username": username}).count() == 0:
        return False
    else:
        return True

def countTokens(username):
    tokens = users.find({
        "Username": username
    })[0]["Tokens"]

    return tokens

#Handles the registration of the user
class Register(Resource):
    #handles it as a post request
    def post(self):
        #gets data entered by the user and assigns it to local variables
        postedData = request.get_json()
        username = postedData["username"]
        password = postedData["password"]

        #if user already exist, tell user to pick a new username
        if UserExist(username):
            retJson = {
                "status": 301,
                "message": "Username already taken, please try something else"
            }
            return jsonify(retJson)

        #hashes pw entered by the user and adds a little salt to it
        hashed_pw = bcrypt.hashpw(password.encode('utf8'), bcrypt.gensalt())

        #insert user in the database with the hashed password
        users.insert({
            "Username":username,
            "Password": hashed_pw,
            "Tokens": 6
        })

        #prepares and return the message to be displayed once user successfully registers
        retJson = {
            "status": 200,
            "message": "User successfully registered"
        }
        return jsonify(retJson)

class Detect(Resource):
    def post(self):
        #gets user imput and assigns it to local variables
        postedData = request.get_json()

        username = postedData["username"]
        password = postedData["password"]
        text1 = postedData["text1"]
        text2 = postedData["text2"]

        #validates that username is registered to use Api
        if not UserExist(username):
            retJson = {
                "status": 302,
                "message": "You need to be registered to use the API"
            }
            return jsonify(retJson)

        #verifies that username and password combination match
        correct_pw = verifyPw(username, password)

        if not correct_pw:
            retJson = {
                "status": 303,
                "message": "incorrect Username / Password combination"
            }
            return jsonify(retJson)

        num_tokens = countTokens(username)

        if num_tokens <= 0:
            retJson = {
                "status": 304,
                "message": "You need to add more tokens to use the API"
            }
            return jsonify(retJson)

        #calculate similarity
        nlp = spacy.load('en_core_web_sm')
        text1 = nlp(text1)
        text2 = nlp(text2)

        #Ratio is a number between 0 and 1, the higher the number, the closer the similarity and prepare response
        ratio = text1.similarity(text2)
        retJson = {
            "status": 200,
            "similarity": ratio,
            "message": "Similarity ratio calculated successfully"
        }

        current_tokens = countTokens(username)
        users.update({
            "Username":username
        }, {
            "$set":{
                "Tokens":current_tokens-1
                }
        })

        return jsonify(retJson)

class Refill(Resource):
    def post(self):

        postedData = request.get_json()

        username = postedData["username"]
        admin_pw = postedData["admin_pw"]
        refill_amount = postedData["refill"]

        if not UserExist(username):
            retJson = {
                "status": 301,
                "message": "Invalid username"
            }
            return jsonify(retJson)

        correct_pw = "admin123"

        if not admin_pw == correct_pw:
            retJson = {
                "status": 302,
                "message": "Invalid password"
            }
            return jsonify(retJson)

        current_tokens = countTokens(username)

        users.update({
            "Username": username
        },{
            "$set": {
                "Tokens": refill_amount + current_tokens
            }
        })

        retJson = {
            "status": 200,
            "message": "User Tokens refilled"
        }

        return jsonify(retJson)


#adds the resources that user will use
api.add_resource(Register, '/register')
api.add_resource(Detect, '/detect')
api.add_resource(Refill, '/refill')



#instantiates application
if __name__=="__main__":
    app.run(host='0.0.0.0')
