from jose import jws
import requests
import sys
import os
import json
from bson import ObjectId
from calendar import timegm
from datetime import datetime
import uuid
import time
import base64
import boto3
import random
import jwt
from jwt.exceptions import InvalidTokenError

sys.path.append('../service')
sys.path.append('../models')
sys.path.append('../enums')
sys.path.append('../entities')

from service.connection import connect_mongo_authprovider, connect_mongo_project, connect_mongo_user,connect_mongo_session,connect_mongo_idpToken,connect_mongo_asset
from enums.response_code import ResponseCode
from enums.response_message import ResponseMessage
from models.response import SuccessResponse, ErrorResponse, Response
from service.validate import validate_inputs
from entities.input import inputHeaderDTO, inputBodyDTO
from entities.output import outputDTO
from service.connection import client

lambda_client = boto3.client('lambda')
collection_authprovider = connect_mongo_authprovider()
collection_project = connect_mongo_project()
collection_user = connect_mongo_user()
collection_session = connect_mongo_session()
collection_idp_token = connect_mongo_idpToken()
collection_asset=connect_mongo_asset()

key_id = os.environ['KMS_KEY_ID_JWT_SIGN']
key_id_encrypt_decrypt_refresh_token= os.environ['KMS_KEY_ENCRYPT_DECRYPT_KEY_ID']
kaiju_issuer_base_url=os.environ['KAIJU_ISSUER_BASE_URL']
version=os.environ['VERSION']
expire_range_non_jwt=60*60
validate_id_token_discord_url_response1='https://discord.com/api/v10/oauth2/@me'
validate_id_token_discord_url_response2='https://discord.com/api/v10/users/@me'

def sign(headers, payload, key_arn, expire_range):
    kms = boto3.client('kms')
    payload['iat'] = int(time.time())
    payload['exp'] = payload['iat'] + expire_range
    payload['auth_time'] = payload['iat']

    token_components = {
        'header': base64.urlsafe_b64encode(bytes(json.dumps(headers), 'utf-8')).decode('utf-8'),
        'payload': base64.urlsafe_b64encode(bytes(json.dumps(payload), 'utf-8')).decode('utf-8').rstrip('=')
    }

    message = token_components['header'] + "." + token_components['payload']

    res = kms.sign(
        Message=message.encode('utf-8'),
        KeyId=key_arn,
        SigningAlgorithm='RSASSA_PKCS1_V1_5_SHA_256',
        MessageType='RAW'
    )

    token_components['signature'] = base64.b64encode(res['Signature']).decode('utf-8').replace('+', '-').replace('/', '_').rstrip('=')

    return {
        'token': token_components['header'] + "." + token_components['payload'] + "." + token_components['signature']
    }

header = {
    "alg": "RS256",
    "typ": "JWT"
}

def find_user_by_email(email):
    user = collection_user.find_one({'email': email})
    return user

def is_jwt(token):
    try:
        jwt.decode(token, options={"verify_signature": False})
        return True
    except InvalidTokenError:
        return False

def generate_uuid_from_string(input_string: str) -> str:
    namespace = uuid.NAMESPACE_DNS
    generated_uuid = uuid.uuid5(namespace, input_string)
    return str(generated_uuid)

def generate_random_string():
    return str(uuid.uuid4())[:6]

def get_random_number():
    min_val = 1000
    max_val = 1800
    step = 200
    index = random.randint(0, (max_val - min_val) // step)
    random_number = min_val + index * step
    return random_number

def get_username_from_email(email):
    return email.split('@')[0]

def encrypt(source, key_id):
    kms = boto3.client('kms')
    params = {
        'KeyId': key_id,
        'Plaintext': source,
    }
    response = kms.encrypt(**params)
    cipher_text_blob = response['CiphertextBlob']
    return base64.b64encode(cipher_text_blob).decode('utf-8')

def authorizeForLogin(event):
    
    session=client.start_session()
    session.start_transaction()
    headers = headers_to_lowercase(event['headers'])
    body = json.loads(event['body'])
    validate_inputs(headers, inputHeaderDTO(many=False))
    validate_inputs(body, inputBodyDTO(many=False))

    auth_provider_id = headers['authproviderid']
    access_key = headers['accesskey']
    token = body['token']
    auth_provider = collection_authprovider.find_one({'_id': ObjectId(auth_provider_id)})
    jwks_url = auth_provider['publicKey']
    project_id = auth_provider['projectId']
    project = collection_project.find_one({'_id': ObjectId(project_id)})
    access_keys = project['accessKeys']
    client_id = auth_provider['clientId']
    issuer = auth_provider['iss']
    authprovider_type = auth_provider['type']
    provider = auth_provider['provider']

    if(access_keys[0]==access_key or access_keys[1]==access_key):
        if(authprovider_type=='custom'):
            response= validate_id_token(token,jwks_url,client_id, issuer)
        elif(authprovider_type=='social'):
            if provider == 'google':
                response = validate_id_token(token, jwks_url, client_id, issuer)
                print("response",response)
            elif(provider=='discord'):
                response=validate_id_token_discord(token,client_id)
        else: 
            raise ErrorResponse(ResponseCode.UNAUTHORIZED_AUTH_PROVIDER,ResponseMessage.UNAUTHORIZED_AUTH_PROVIDER)
        
        if(authprovider_type=='custom') or (authprovider_type=='social' and provider=='google'):
            valid_token, user_name, email, profile_image, expire_range, aud, create_time, exp = response
        else:
            valid_token, user_name, email, profile_image = response

        if valid_token:
            user = find_user_by_email(email)
            if(user_name==None):
                user_name=get_username_from_email(email)

            if user:
                user_id = user['_id']
                user_details = {
                    'name': user_name,
                    'userProfileImage': profile_image,
                }
                collection_user.update_one({'_id': user['_id']}, {'$set': user_details},session=session)
            else:
                first_name = user_name.split(" ")[0]
                random_string = generate_random_string()
                user_name = first_name + random_string

                existing_usernames = collection_user.count_documents({'username': user_name})

                while existing_usernames > 0:
                    random_string = generate_random_string()  
                    user_name = first_name + random_string
                    existing_usernames = collection_user.count_documents({'username': user_name})

                # Create a new user
                add_user_details ={
                    'name': user_name,
                        'email': email,
                        'userProfileImage': profile_image,
                        'blockchains': {
                            'evm': {
                                'walletAddress': "",
                                'walletAddressOwner': "",
                            },
                            'evmEOA': {
                                'walletAddress': "",
                                'walletAddressOwner': "",
                            },
                            'solana': {
                                'walletAddress': "",
                                'walletAddressOwner': "",
                            },
                            'xrpl': {
                                'walletAddress': "",
                                'walletAddressOwner': "",
                            },
                        },
                        'username': user_name,
                        'ens': "",
                        'bio': "",
                        'website': {
                            'title': "",
                            'value': "",
                        },
                        'instagram': {
                            'title': "",
                            'value': "",
                        },
                        'twitter': {
                            'title': "",
                            'value': "",
                        },
                        'discord': {
                            'title': "",
                            'value': "",
                        },
                        'youtube': {
                            'title': "",
                            'value': "",
                        },
                        'linkedin': {
                            'title': "",
                            'value': "",
                        },
                        'userLevel': "USER",
                        'walletVersion': "v2",
                        'publicNFTProfile': True,
                        'analytics': False,
                        'currency': "USD",
                        'developerId': None,
                        'isDeveloper': False,
                        'userStatus': "inactive",
                }
                try:
                    result_user = collection_user.insert_one(add_user_details,session=session)
                    user_id = result_user.inserted_id 
                except Exception as err:
                    if (err.code == 11000):
                        print("duplicate key issue, duplicate key issue")
                        user= collection_user.find_one(email)
                        user_already_exist=True
                        delay_time=get_random_number()
                        time.sleep(delay_time)
                    else:
                        raise ErrorResponse(ResponseCode.ERROR_ON_SAAS_GET_WALLET,ResponseMessage.ERROR_ON_SAAS_GET_WALLET)
                      
            session.commit_transaction()
            payload = {
                'version': version,
                'scope': "core getWallet signTx",
                'aud': project_id,
                'email': email,
                'userId': str(user_id),
                'userLevel':"USER"
            }
            payload_jwt = {
                'sub': str(user_id),
                'iss': kaiju_issuer_base_url + project_id,
                'version': version,
                'scope': "core getWallet signTx",
                'aud': project_id,
                'email': email,
                'userLevel':"USER"
            }

            payload_string = json.dumps(payload)
            iat = int(time.time())

            token_type_bool=is_jwt(token)
            if token_type_bool:
                exp = iat + expire_range
                expiry_time = exp
                token_type="JWT"
                token_info=""
            else:
                expire_range=expire_range_non_jwt
                exp=iat+expire_range
                expiry_time=exp
                token_type="non-JWT"
                token_info=token
                aud=""
                create_time=""

            result_of_the_sign = sign(header, payload_jwt, key_id, expire_range)
            jwt_token = result_of_the_sign['token'] 

            return {'session_token': payload_string, 'expiration': expiry_time, 'session_jwt_token': jwt_token, 'user_id': user_id,"email":email,"aud":aud,"create_time":create_time ,"token_type":token_type,"token":token_info}
        else:
            raise ErrorResponse(ResponseCode.INVALID_TOKEN_AUTHORIZE_FOR_LOGIN,ResponseMessage.INVALID_TOKEN_AUTHORIZE_FOR_LOGIN)
    else:
        raise ErrorResponse(ResponseCode.UNAUTHORIZED_ACCESS_KEY,ResponseMessage.UNAUTHORIZED_ACCESS_KEY)

def validate_id_token(id_token,jwks_url,client_id, issuer):
    response = requests.get(jwks_url)
    certs=response.json()
    header = jws.get_unverified_header(id_token)
    kid = header.get("kid")
    key = next(key for key in certs['keys'] if key['kid'] == kid)
    payload = jws.verify(id_token, key, ["RS256"], verify=True)
    claims = json.loads(payload.decode("utf-8"))
    username = claims.get("name")
    email = claims.get("email")
    profile_image = claims.get("picture")
    exp=claims.get("exp")
    iat=claims.get("iat")
    expire_range=exp-iat
    aud=claims.get("aud")
    if exp<time.time():
        raise ErrorResponse(ResponseCode.TOKEN_EXPIRED,ResponseMessage.TOKEN_EXPIRED)
    valid_claim = validate_claims(claims,client_id,issuer)
    return valid_claim, username, email, profile_image,expire_range,aud,iat,exp
        
def validate_claims(claims,client_id,issuer):
    now = timegm(datetime.utcnow().utctimetuple())
    exp = int(claims["exp"])
    aud = claims["aud"]
    iss = claims["iss"]
    if exp < (now):
        return False
    if aud != client_id: 
        return False
    if iss != issuer: 
        return False
    return True

def validate_id_token_discord(token,client_id):
    headers = {'Authorization': f'Bearer {token}'}
    #to get username, profile image from discord token
    response1 = requests.get(validate_id_token_discord_url_response1, headers=headers)
    #to get email from discord token
    response2 = requests.get(validate_id_token_discord_url_response2, headers=headers)

    response1_json = response1.json()
    response2_json = response2.json()

    username = response1_json.get("user", {}).get("global_name")
    email = response2_json.get("email")
    avatar_hash = response2_json.get("avatar")
    user_id = response2_json.get("id")
    if avatar_hash is not None:
        profile_image = f"https://cdn.discordapp.com/avatars/{user_id}/{avatar_hash}.png"
    else:
        profile_image = None 

    if response1.status_code == 200:
        response_data = response1.json()
        if 'application' in response_data and 'id' in response_data['application']:
            if response_data['application']['id'] == client_id:
                return True, username, email, profile_image
            else:
                raise ErrorResponse(ResponseCode.INVALID_CLIENT_ID,ResponseMessage.INVALID_CLIENT_ID)
        else:
            raise ErrorResponse(ResponseCode.INVALID_TOKEN_DISCORD_LOGIN,ResponseMessage.INVALID_TOKEN_DISCORD_LOGIN)
    elif response1.status_code == 401:
        raise ErrorResponse(ResponseCode.INVALID_TOKEN_DISCORD_LOGIN,ResponseMessage.INVALID_TOKEN_DISCORD_LOGIN)
    elif response1.status_code == 403:
        raise ErrorResponse(ResponseCode.PERMISSION_ERROR,ResponseMessage.PERMISSION_ERROR)
    else:
        raise Exception(f"Unexpected status code: {response1.status_code}")
        
def headers_to_lowercase(headers):
    headers_lowercase = {key.lower(): value for key, value in headers.items()}
    return headers_lowercase

def login(event, context):
    try:
        session=client.start_session()
        session.start_transaction()
        result = authorizeForLogin(event)

        token_type=result['token_type']
        email=result['email']
        aud=result['aud']
        create_time=result['create_time']
        token=result['token']
        session_token = result['session_token']
        session_jwt_token = result['session_jwt_token']
        user_id = result['user_id']
        expiration_session_token = result['expiration']

        if token_type=='JWT':
            string_for_token=email+aud+str(create_time)
            idp_token = generate_uuid_from_string(string_for_token)
        else:
            idp_token=token

        existing_idp_token=collection_idp_token.find_one({'token': idp_token})

        if existing_idp_token:
            raise ErrorResponse(ResponseCode.IDP_TOKEN_EXISTS,ResponseMessage.IDP_TOKEN_EXISTS)
        else:
            collection_idp_token.insert_one({
                'token': idp_token,
                'tokenType': token_type,
                'expirationTime': expiration_session_token
            },session=session)

        encrypted_session_token = encrypt(session_token, key_id_encrypt_decrypt_refresh_token)
        existing_user = collection_session.find_one({'userId': str(user_id)},session=session)

        if existing_user:
            session_id = existing_user['_id']
            collection_session.delete_one({ '_id': session_id },session=session)
                
            collection_session.insert_one({
                '_id': session_id,
                'userId': str(user_id),
                'sessionToken': encrypted_session_token,
                'sessionExpiration': expiration_session_token
            },session=session)

        else:
            session_id = str(uuid.uuid4())
            collection_session.insert_one({
                '_id': session_id,
                'userId': str(user_id),
                'sessionToken': encrypted_session_token,
                'sessionExpiration': expiration_session_token
            },session=session)
        output_result={
            'sessionToken': session_id,
            'JWTToken': session_jwt_token,
        }
        validate_inputs(output_result, outputDTO(many=False))
        session.commit_transaction() 
        return SuccessResponse(output_result).generate()
    except Exception as e:
        session.abort_transaction()
        return (e if isinstance(e, Response) else ErrorResponse(ResponseCode.ERROR,str(e))).generate()
    finally:
        session.end_session()
