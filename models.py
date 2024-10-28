from database import db

class Key(db.Model):
    __tablename__ = 'key'
    
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    kid = db.Column(db.String(50), unique=True, nullable=False)
    private_key = db.Column(db.Text, nullable=False)
    exp = db.Column(db.Integer, nullable=False)


