import datetime
import json
import logging
import requests

from lib.crits.exceptions import CRITsOperationalError
from lib.crits.vocabulary.indicators import IndicatorThreatTypes as itt
from lib.crits.vocabulary.indicators import IndicatorAttackTypes as iat
from bson.objectid import ObjectId
from pymongo import MongoClient

log = logging.getLogger()

class CRITsDBAPI():

    def __init__(self, mongo_uri='mongodb://localhost:27017', db_name='crits'):
        self.mongo_uri = mongo_uri
        self.db_name = db_name
        self.client = None
        self.db = None

    def connect(self):
        self.client = MongoClient(self.mongo_uri)
        self.db = self.client[self.db_name]

    def find(self, collection, query):
        obj = getattr(self.db, collection)
        result = obj.find( query )
        return result

    def find_one(self, collection, query):
        obj = getattr(self.db, collection)
        result = obj.find_one( query )
        return result

    def add_embedded_campaign(self, id, collection, campaign, confidence, analyst,
                               date, description):
        if type(id) is not ObjectId:
            id = ObjectId(id)
        # TODO: Make sure the object does not already have the campaign
        # Return if it does. Add it if it doesn't
        obj = getattr(self.db, collection)
        result = obj.find( { '_id' : id, 'campaign.name' : campaign } )
        if result.count() > 0:
            return
        else:
            log.debug('Adding campaign to set: {}'.format(campaign))
            campaign_obj = {
                'analyst' : analyst,
                'confidence' : confidence,
                'date' : date,
                'description' : description,
                'name' : campaign
            }
            result = obj.update( { '_id' : id },
                { '$push' : { 'campaign' : campaign_obj } } )
            return result

    def add_bucket_list_item(self, id, collection, item):
        if type(id) is not ObjectId:
            id = ObjectId(id)
        obj = getattr(self.db, collection)
        result = obj.update(
            { '_id' : id },
            { '$addToSet' : { 'bucket_list' : item } }
        )
        return result
