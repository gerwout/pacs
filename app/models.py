from sqlalchemy import Column
from app import db
from app import models

class MacAddress(db.Model):
    __tablename__ = 'mac_addresses'
    id = Column(db.Integer, primary_key=True)
    comp_id = Column(db.Integer, db.ForeignKey('computer.id'), nullable=False, index=True)
    mac = Column(db.String(64), nullable=False)

    # this list will contain the mac addresses that should be ignored in all instances
    # this is usually a special virtual network adapter like the NPCAP localhost adapter
    # connections should never originate from these mac addresses, hence we will ignore them
    ignore_mac_list = ["02004C4F4F50"]

    def __repr__(self):
        return ':'.join(self.mac[i:i+2] for i in range(0, len(self.mac), 2))

class Source(db.Model):
    __tablename__ = 'source'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), index=True, unique=True, nullable=False)

    def __repr__(self):
        return self.name

class Computer(db.Model):
    __tablename__ = 'computer'
    id = Column(db.Integer, primary_key=True)
    name = Column(db.String(64), index=True, unique=False)
    description = Column(db.String(120), index=True, unique=False)
    last_logon_name = Column(db.String(120), index=True, unique=False)
    ignore_av_check = Column(db.Boolean, index=True, unique=False)
    source_id = Column(db.Integer, index=True, nullable=False)
    mac_addresses = db.relationship('MacAddress', backref='computer')

    def get_source(self):
        return models.Source.query.filter_by(id=self.source_id).one()

    def __repr__(self):
        return '<Computer {}>'.format(self.name)


