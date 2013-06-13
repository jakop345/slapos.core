# -*- coding: utf-8 -*-

import collections
import hashlib
import logging

import lxml.etree
import prettytable

from slapos.cli.config import ConfigCommand
from slapos.proxy import ProxyConfig
from slapos.proxy.db_version import DB_VERSION

import sqlalchemy
from sqlalchemy import Column, String, ForeignKey
import sqlalchemy.orm
from sqlalchemy.ext.declarative import declarative_base


Base = declarative_base()


class Partition(Base):
    __tablename__ = 'partition' + DB_VERSION

    reference = Column(String(255), primary_key=True)
    slap_state = Column(String(255), default='free')
    software_release = Column(String(255))
    xml = Column(String)
    connection_xml = Column(String)
    slave_instance_list = Column(String)
    software_type = Column(String(255))
    partition_reference = Column(String(255))
    requested_by = Column(String(255))  # only used for debugging,
                                        # slapproxy does not support proper scope
    requested_state = Column(String(255), nullable=False, default='started')


class Computer(Base):
    __tablename__ = 'computer' + DB_VERSION

    address = Column(String(255), primary_key=True)
    netmask = Column(String(255), primary_key=True)


class Software(Base):
    __tablename__ = 'software' + DB_VERSION

    url = Column(String(255), primary_key=True)

    @property
    def md5(self):
        return hashlib.md5(self.url).hexdigest()


class Slave(Base):
    __tablename__ = 'slave' + DB_VERSION

    reference = Column(String(255), primary_key=True)
    connection_xml = Column(String)
    hosted_by = Column(String(255))
    asked_by = Column(String(255))  # only used for debugging,
                                    # slapproxy does not support proper scope


class PartitionNetwork(Base):
    __tablename__ = 'partition_network' + DB_VERSION

    partition_reference = Column(String(255),
                                 ForeignKey(Partition.reference),
                                 primary_key=True)
    reference = Column(String(255))
    address = Column(String(255), primary_key=True)
    netmask = Column(String(255))

    partition = sqlalchemy.orm.relationship(Partition)


class ProxyShowCommand(ConfigCommand):
    """
    display proxy instances and parameters
    """

    log = logging.getLogger('proxy')

    def get_parser(self, prog_name):
        ap = super(ProxyShowCommand, self).get_parser(prog_name)

        ap.add_argument('-u', '--database-uri',
                        help='URI for sqlite database')

        ap.add_argument('--computers',
                        help='view computer information',
                        action='store_true')

        ap.add_argument('--software',
                        help='view software releases',
                        action='store_true')

        ap.add_argument('--partitions',
                        help='view partitions',
                        action='store_true')

        ap.add_argument('--slaves',
                        help='view slave instances',
                        action='store_true')

        ap.add_argument('--params',
                        help='view published parameters',
                        action='store_true')

        ap.add_argument('--network',
                        help='view network settings',
                        action='store_true')

        return ap

    def take_action(self, args):
        configp = self.fetch_config(args)
        conf = ProxyConfig(logger=self.log)
        conf.mergeConfig(args, configp)
        conf.setConfig()
        do_show(conf=conf)


def coalesce(*seq):
    el = None
    for el in seq:
        if el is not None:
            return el
    return el


def log_params(logger, session):
    for partition in session.query(Partition):
        if not partition.connection_xml:
            continue

        xml = str(partition.connection_xml)
        logger.info('%s: %s (type %s)', partition.reference, partition.partition_reference, partition.software_type)
        instance = lxml.etree.fromstring(xml)
        for parameter in list(instance):
            name = parameter.get('id')
            text = parameter.text
            if text and name in ('ssh-key', 'ssh-public-key'):
                text = text[:20] + '...' + text[-20:]
            logger.info('    %s = %s', name, text)


def log_table(logger, objects, tablename, columns=None):
    if columns is None:
        columns = []

    pt = prettytable.PrettyTable(columns)
    # https://code.google.com/p/prettytable/wiki/Tutorial

    rows = [
        [coalesce(getattr(obj, col), '-') for col in columns]
        for obj in objects
    ]

    if rows:
        logger.info('table %s', tablename)
    else:
        logger.info('table %s: empty', tablename)
        return

    for row in rows:
        pt.add_row(row)

    for line in pt.get_string(border=True, padding_width=0, vrules=prettytable.NONE).split('\n'):
        logger.info(line)


def log_computer_table(logger, session):
    computers = session.query(Computer)
    log_table(logger, computers, Computer.__tablename__,
              columns=['address', 'netmask'])


def log_software_table(logger, session):
    software_objs = session.query(Software)
    log_table(logger, software_objs, Software.__tablename__,
              columns=['url', 'md5'])


def log_partition_table(logger, session):
    partitions = session.query(Partition).filter(Partition.slap_state != 'free')
    log_table(logger, partitions, Partition.__tablename__,
              columns=[
                  'reference', 'slap_state', 'software_release',
                  'software_type', 'partition_reference', 'requested_by',
                  'requested_state'
              ])


def log_slave_table(logger, session):
    slaves = session.query(Slave)
    log_table(logger, slaves, Slave.__tablename__,
              columns=['reference', 'hosted_by', 'asked_by'])


def log_network(logger, session):
    partition_networks = [
        pn for pn in session.query(PartitionNetwork)
        if pn.partition.slap_state != 'free'
    ]

    addr = collections.defaultdict(list)

    for pn in partition_networks:
        addr[pn.partition_reference].append(pn.address)

    for partition_reference in sorted(addr.keys()):
        addresses = addr[partition_reference]
        logger.info('%s: %s', partition_reference, ', '.join(addresses))


def do_show(conf):
    conf.logger.debug('Using database: %s', conf.database_uri)

    engine = sqlalchemy.create_engine('sqlite:///%s' % conf.database_uri)
    Session = sqlalchemy.orm.sessionmaker(bind=engine)
    session = Session()

    call_table = [
        (conf.computers, log_computer_table),
        (conf.software, log_software_table),
        (conf.partitions, log_partition_table),
        (conf.slaves, log_slave_table),
        (conf.params, log_params),
        (conf.network, log_network)
    ]

    if not any(flag for flag, func in call_table):
        to_call = [func for flag, func in call_table]
    else:
        to_call = [func for flag, func in call_table if flag]

    for idx, func in enumerate(to_call):
        func(conf.logger, session)
        if idx < len(to_call) - 1:
            conf.logger.info(' ')
