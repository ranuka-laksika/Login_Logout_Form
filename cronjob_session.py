import os
from datetime import datetime, timedelta
from pymongo import MongoClient
from bson.objectid import ObjectId

from enums.response_code import ResponseCode
from enums.response_message import ResponseMessage
from models.response import SuccessResponse, ErrorResponse, Response

client = MongoClient(os.environ["MONGODB_URL"])
database = client[os.environ["DB_NAME"]]
session_collection = database["session"]
setting_collection = database["setting"]

def delete_expired_sessions(start_key, end_key):
    session=client.start_session()
    session.start_transaction()

    query = {}
    if start_key:
        query["sessionExpiration"] = {"$gte": start_key}
    if end_key:
        if "sessionExpiration" not in query:
            query["sessionExpiration"] = {}
        query["sessionExpiration"]["$lt"] = end_key
    unprocessed_sessions = list(session_collection.find(query).sort("sessionExpiration", 1))

    if not unprocessed_sessions:
        return "No sessions"
    
    now=int(datetime.utcnow().timestamp()) 
    expired_sessions = [session for session in unprocessed_sessions if session["sessionExpiration"] < now]
    
    if not expired_sessions:
        return "No sessions to delete"
    
    expired_session_ids = [session["_id"] for session in expired_sessions]
    session_collection.delete_many({"_id": {"$in": expired_session_ids}},session=session)
    session.commit_transaction()

def cronjob_session(event, context):
    try:
        session=client.start_session()
        session.start_transaction()
        end_key = None
        session_collection.create_index([('sessionExpiration', 1)],session=session)
        first_session = session_collection.find_one(sort=[('sessionExpiration', 1)],session=session)
        if not first_session:
            now = int(datetime.utcnow().timestamp()) 
            end_key = now
            setting_collection.update_one({}, {"$set": {"session_clear_end_key": end_key}},session=session)
            return None
        
        start_key_object = setting_collection.find_one({}, {"session_clear_end_key": 1},session=session)
        start_key = start_key_object.get("session_clear_end_key", None)
        execution_time_period = 0

        while execution_time_period < 12*60:
            start_time = (datetime.utcnow().timestamp())
            end_key = start_key + ( 2 * 60 * 60)
            response = delete_expired_sessions(start_key, end_key)

            if (response == "No sessions" or response=="No sessions to delete"):
                first_session = session_collection.find_one(sort=[('sessionExpiration', 1)],session=session)
                end_key = first_session["sessionExpiration"]
                break

            start_key = end_key
            end_time = (datetime.utcnow().timestamp())
            execution_time = (end_time - start_time)
            execution_time_period += execution_time
                
        setting_collection.update_one({}, {"$set": {"session_clear_end_key": end_key}},session=session)
        session.commit_transaction()

    except Exception as error:
        session.abort_transaction()
        return (error if isinstance(error, Response) else ErrorResponse(ResponseCode.ERROR,str(error))).generate()
    finally:
        session.end_session()
