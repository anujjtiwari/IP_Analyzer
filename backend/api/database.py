from pymongo import MongoClient

DB_HOST = "localhost"
DB_PORT = 27017
DB_USER = "admin_ip_analyzer"
DB_PASSWORD = "root_ip_analyzer"
DB_NAME = "ip_analyzer"

mongo_client = MongoClient(
    host=DB_HOST,
    port=DB_PORT,
    username=DB_USER,
    password=DB_PASSWORD,
    authSource=DB_NAME
)

db_handle = mongo_client[DB_NAME]
collection_handle_users = db_handle['users']
collection_handle_temp_users = db_handle['temp_users']
collection_handle_queries = db_handle['queries']
