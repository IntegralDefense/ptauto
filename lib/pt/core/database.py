import json
import logging
import os
from datetime import datetime

from lib.pt.common.config import Config

from sqlalchemy import create_engine, Column
from sqlalchemy import Integer, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm import validates

Base = declarative_base()

log = logging.getLogger()


class Cache(Base):
    __tablename__ = 'cache'

    id = Column(Integer, primary_key=True)
    created_date = Column(DateTime, default=datetime.utcnow)
    modified_date = Column(DateTime, default=datetime.utcnow)
    user = Column(String)
    query = Column(String)
    cache_file = Column(String)

    def __repr__(self):
        return '<Cache({}, {})>'.format(self.id, self.query)

    @validates('cache_file')
    def validate_cache_file(self, key, value):
        assert value != ''
        return value


class Database():

    def __init__(self):
        cfg = Config()

        if cfg.db.connection:
            if 'sqlite:///' in cfg.db.connection:
                db_file = cfg.db.connection[10:]
                if not os.path.exists(os.path.dirname(db_file)):
                    os.makedirs(os.path.dirname(db_file))
            self._connect_database(cfg.db.connection)
        else:
            log.error('sqlite:/// not found')
            raise Exception('Ensure sqlite:////path/to/pt.db exists in your '
                            'configuration file.')

        # Create the schema
        Base.metadata.create_all(self.engine)

        self.Session = sessionmaker(bind=self.engine)

    def _connect_database(self, connection_string):
        try:
            self.engine = create_engine(connection_string,
                                        connect_args={
                                            'check_same_thread': False
                                        })
        except ImportError as e:
            lib = e.message.split()[-1]
            raise ImportError("Missing database driver, unable to "
                              "import %s (install with `pip "
                              "install %s`)" % (lib, lib))

    def add_cache_file(self, created_date, modified_date, user, query,
                       cache_file):
        """
        Add a cache file to the database.

        @param created_date: The initial creation date. datetime.utcnow by
                            default
        @param modified_date: The initial modified date. datetime.utcnow by
                            default
        @param user: The user that initiated the PT query
        @param query: The query itself
        @param cache_file: The location on disk of the cached results
        """
        log.debug('Adding new cache file to the database for the query: {}'
                  ' and file: {}'.format(query, cache_file))
        session = self.Session()

        cache = Cache(
            created_date=created_date,
            modified_date=modified_date,
            user=user,
            query=query,
            cache_file=cache_file
            )

        session.add(cache)
        try:
            session.commit()
        except SQLAlchemyError as e:
            log.error("Database error adding cache: {0}".format(e))
            session.rollback()
        finally:
            session.close()

        return cache

    def update_cache_file(self, query, user, cache_file):
        log.debug('User {} is updating the cache for query {}'.format(user,
                                                                      query))
        session = self.Session()
        cache_entry = session.query(Cache).filter(Cache.query == query).first()
        if not cache_entry:
            log.warning('User {} tried to update the cache for query {}, but '
                        'it was not found.'.format(user, query))
            return False
        cache_entry.user = user
        cache_entry.cache_file = cache_file
        cache_entry.modified_date = datetime.utcnow()
        session.commit()
        log.debug('User {} updated the cache for query {}'.format(user,
                                                                  query))
        return True

    def get_cache_file(self, query):
        session = self.Session()
        cache_entry = session.query(Cache).filter(Cache.query == query).first()
        if not cache_entry:
            return False
        return cache_entry.cache_file

    def has_cache_entry(self, query):
        session = self.Session()
        cache_entry = session.query(Cache).filter(Cache.query == query).first()
        if cache_entry:
            return True
        return False

    def get_cache_modified_date(self, query):
        session = self.Session()
        cache_entry = session.query(Cache).filter(Cache.query == query).first()
        if not cache_entry:
            log.warning('User {} tried to update the cache for query {}, but '
                        'it was not found.'.format(user, query))
            return False
        return cache_entry.modified_date

    def add_results_to_cache(self, query, user, results, cache_file):
        log.info('Adding results to cache for query: {}'.format(query))
        # Save the results to a cache_file
        with open(cache_file, 'w') as fp:
            json.dump(results, fp)
        current_cache_file = self.get_cache_file(query)
        if current_cache_file:
            # If we have a cache entry already, delete the old
            os.remove(current_cache_file)
            # then update the entry with the new cache file
            self.update_cache_file(query, user, cache_file)
        else:
            # Add a new entry
            created_date = datetime.utcnow()
            modified_date = datetime.utcnow()
            self.add_cache_file(created_date, modified_date, user, query,
                                cache_file)

    def _get_or_create(self, session, model, **kwargs):
        """Get an ORM instance or create it if not exist.
        @param session: SQLAlchemy session object
        @param model: model to query
        @return: row instance
        """
        instance = session.query(model).filter_by(**kwargs).first()
        if instance:
            return instance
        else:
            instance = model(**kwargs)
            return instance
