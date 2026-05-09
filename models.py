from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

db = SQLAlchemy()

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), default='student')
    reg_number = db.Column(db.String(50), unique=True, nullable=True)
    department = db.Column(db.String(100), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    documents = db.relationship('Document', backref='owner', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def to_dict(self):
        return {
            'id': self.id,
            'full_name': self.full_name,
            'email': self.email,
            'role': self.role,
            'reg_number': self.reg_number,
            'department': self.department,
            'created_at': self.created_at.isoformat()
        }


class Document(db.Model):
    __tablename__ = 'documents'
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(200), nullable=False)
    original_name = db.Column(db.String(200), nullable=False)
    file_hash = db.Column(db.String(64), unique=True, nullable=False)
    block_hash = db.Column(db.String(64), nullable=False)
    block_index = db.Column(db.Integer, nullable=False)
    cert_fingerprint = db.Column(db.String(200), nullable=False)
    signature = db.Column(db.Text, nullable=False)
    doc_type = db.Column(db.String(50), default='general')
    status = db.Column(db.String(20), default='active')
    qr_code_path = db.Column(db.String(200), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    signed_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=True)

    def to_dict(self):
        return {
            'id': self.id,
            'filename': self.filename,
            'original_name': self.original_name,
            'file_hash': self.file_hash,
            'block_hash': self.block_hash,
            'block_index': self.block_index,
            'doc_type': self.doc_type,
            'status': self.status,
            'signed_at': self.signed_at.isoformat(),
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            'owner_name': self.owner.full_name if self.owner else None,
            'owner_email': self.owner.email if self.owner else None,
            'reg_number': self.owner.reg_number if self.owner else None
        }


class AuditLog(db.Model):
    __tablename__ = 'audit_logs'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    action = db.Column(db.String(100), nullable=False)
    details = db.Column(db.Text, nullable=True)
    ip_address = db.Column(db.String(50), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    success = db.Column(db.Boolean, default=True)

    def to_dict(self):
        return {
            'id': self.id,
            'action': self.action,
            'details': self.details,
            'ip_address': self.ip_address,
            'timestamp': self.timestamp.isoformat(),
            'success': self.success
        }
