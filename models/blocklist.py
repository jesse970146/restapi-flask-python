from db import db
class BlockListModel(db.Model):
    __tablename__ = "blocklists"

    id  = db.Column(db.Integer, primary_key = True)
    expired  = db.Column(db.String(), nullable = False)