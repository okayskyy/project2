from flask_sqlalchemy import SQLAlchemy

# Initialize SQLAlchemy
db = SQLAlchemy()

def init_db(app):
    # Configure the database URI (SQLite in this case)
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///totally_not_my_privateKeys.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    db.init_app(app)

