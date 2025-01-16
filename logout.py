import sys
from calendar import timegm
from datetime import datetime

sys.path.append('../../service')
sys.path.append('../../models')
sys.path.append('../../enums')
sys.path.append('../../entites')

from service.connection import connect_mongo_authprovider, connect_mongo_project, connect_mongo_user,connect_mongo_session
from enums.response_code import ResponseCode
from enums.response_message import ResponseMessage
from models.response import SuccessResponse, ErrorResponse, Response
from service.validate import validate_inputs
from entities.logout import logoutDTO

from service.connection import client

collection_authprovider = connect_mongo_authprovider()
collection_project = connect_mongo_project()
collection_user = connect_mongo_user()
collection_session = connect_mongo_session()

def logout(event,context):
    try:
        session=client.start_session()
        session.start_transaction()  
        headers=event["headers"]
        validate_inputs(headers,logoutDTO(many=False))
        session_id=headers["sessionId"]   
        now = datetime.utcnow()
        
        existing_session = collection_session.find_one({ "_id": session_id },session=session)
        if not existing_session:
            raise ErrorResponse(ResponseCode.SESSION_DOESNT_EXIST,ResponseMessage.SESSION_DOESNT_EXIST)
        
        collection_session.delete_one({ "_id": session_id },session=session)
        session.commit_transaction()

        return SuccessResponse({
            "message": "Successfully logged out."
        }).generate()

    except Exception as e:
        session.abort_transaction()
        return (e if isinstance(e, Response) else ErrorResponse(ResponseCode.ERROR,ResponseMessage.ERROR+str(e))).generate()
    
    finally:
        session.end_session()