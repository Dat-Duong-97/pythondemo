from mongoengine import connect, disconnect, DynamicDocument, IntField, StringField, ListField, ReferenceField
import hashlib
from simpleflake import simpleflake

def get_uuid():
    return str(simpleflake())

def md5(text):
    return hashlib.md5(str(text).encode('utf-8')).hexdigest()

class Token(DynamicDocument):
    meta = {"collection":"token"}
    id = StringField(primary_key=True, default = get_uuid)
    userId = StringField()
    token = StringField()

class User(DynamicDocument):
    meta = {"collection": "account"}
    id = StringField(primary_key=True, default = get_uuid)
    email = StringField(max_length=50)
    name = StringField(max_length=50)
    age = IntField(max_value=100)
    password = StringField()
    token = ListField(ReferenceField(Token))


