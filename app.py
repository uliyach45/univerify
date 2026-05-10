import os, ssl, qrcode
import logging
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)
from flask import Flask, request, jsonify, render_template, redirect, url_for, send_from_directory
from flask_login import LoginManager, login_required, current_user
from werkzeug.utils import secure_filename
from datetime import datetime, timezone, timedelta
from models import db, User, Document, AuditLog
from auth import auth, log_action
from blockchain import Blockchain
from tls_auth import compute_file_hash, sign_file_hash, get_cert_fingerprint, extract_cert_from_request
from email_sender import generate_token, verify_token

app = Flask(__name__)
app.secret_key = "univerify_super_secret_2026"
import os
# db in app root
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///univerify.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['QR_FOLDER'] = 'static/qrcodes'

os.makedirs('static/qrcodes', exist_ok=True)
os.makedirs('uploads', exist_ok=True)

db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'auth.login'
login_manager.login_message = 'Please login first!'

app.register_blueprint(auth)

blockchain = Blockchain()

ALLOWED_EXTENSIONS = {"pdf", "docx", "xlsx", "txt"}
USER_KEY_PATH = "certs/user.key"
USER_CERT_PATH = "certs/user.crt"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def generate_qr(doc_id, file_hash):
    verify_url = f"https://uliyach45-univerify.hf.space/public/verify/{file_hash}"
    qr = qrcode.QRCode(version=1, box_size=8, border=4)
    qr.add_data(verify_url)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    path = f"static/qrcodes/doc_{doc_id}_{file_hash[:8]}.png"
    img.save(path)
    return path

# ─────────────────────────────────────────────
# PAGE ROUTES
# ─────────────────────────────────────────────


@app.route('/login-qr')
def login_qr():
    import qrcode, io
    from flask import send_file
    login_url = "https://uliyach45-univerify.hf.space/login"
    qr = qrcode.QRCode(version=1, box_size=8, border=4)
    qr.add_data(login_url)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    buf.seek(0)
    return send_file(buf, mimetype='image/png')


@app.route('/verify-qr')
def verify_qr():
    import qrcode, io
    from flask import send_file
    url = "https://uliyach45-univerify.hf.space/verify_public"
    qr = qrcode.QRCode(version=1, box_size=8, border=4)
    qr.add_data(url)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    buf.seek(0)
    return send_file(buf, mimetype='image/png')

@app.route('/')
def index():
    if current_user.is_authenticated:
        if current_user.role == 'admin':
            return redirect(url_for('dashboard'))
        return redirect(url_for('student_portal'))
    return render_template('index.html')

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role != 'admin':
        return redirect(url_for('student_portal'))
    total_docs = Document.query.count()
    total_users = User.query.count()
    active_docs = Document.query.filter_by(status='active').count()
    revoked_docs = Document.query.filter_by(status='revoked').count()
    recent_docs = Document.query.order_by(Document.signed_at.desc()).limit(5).all()
    recent_logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(10).all()
    chain_valid = blockchain.is_chain_valid()
    return render_template('dashboard.html',
        total_docs=total_docs, total_users=total_users,
        active_docs=active_docs, revoked_docs=revoked_docs,
        recent_docs=recent_docs, recent_logs=recent_logs,
        chain_valid=chain_valid, chain_length=len(blockchain.chain))

@app.route('/student')
@login_required
def student_portal():
    my_docs = Document.query.filter_by(user_id=current_user.id).order_by(Document.signed_at.desc()).all()
    return render_template('student_portal.html', documents=my_docs)

@app.route("/security")
def security_page():
    return render_template("security.html")

@app.route('/explorer')
@login_required
def explorer_page():
    chain_data = [b.to_dict() for b in blockchain.chain]
    return render_template('explorer.html', chain=chain_data)

@app.route('/verify')
def verify_page():
    return render_template('verify.html')

@app.route('/verify_public', methods=['GET','POST'])
def verify_public_page():
    import hashlib
    from flask import session, request as freq
    if not current_user.is_authenticated:
        session['verify_count'] = session.get('verify_count', 0)
        if freq.method == 'POST':
            if False:  # handled by frontend
                return render_template('verify_public.html', block=None, doc=None, file_hash=None, limit_reached=True)
            session['verify_count'] += 1
    if request.method == 'POST':
        f = request.files.get('file')
        if f:
            file_hash = hashlib.sha256(f.read()).hexdigest()
            block = blockchain.query_by_hash(file_hash)
            doc = Document.query.filter_by(file_hash=file_hash).first()
            return render_template('verify_public.html', block=block, doc=doc, file_hash=file_hash, verified=True)
    file_hash = request.args.get('hash')
    if file_hash:
        block = blockchain.query_by_hash(file_hash)
        doc = Document.query.filter_by(file_hash=file_hash).first()
        return render_template('verify_public.html', block=block, doc=doc, file_hash=file_hash, verified=True)
    return render_template('verify_public.html', block=None, doc=None, file_hash=None)
@app.route('/public/verify/<file_hash>')
def public_verify(file_hash):
    block = blockchain.query_by_hash(file_hash)
    doc = Document.query.filter_by(file_hash=file_hash).first()
    return render_template('verify_public.html', block=block, doc=doc, file_hash=file_hash, verified=True)

# ─────────────────────────────────────────────
# API: SIGN DOCUMENT
# ─────────────────────────────────────────────

@app.route('/api/sign', methods=['POST'])
@login_required
def sign_document():
    if current_user.role not in ['admin']:
        return jsonify({'error': 'Only admins can sign documents'}), 403

    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400

    file = request.files['file']
    student_email = request.form.get('student_email', '').strip()
    doc_type = request.form.get('doc_type', 'general').strip()
    expiry_days = int(request.form.get('expiry_days', 0))

    if not file or not allowed_file(file.filename):
        return jsonify({'error': 'Invalid file type'}), 400

    file_bytes = file.read()
    file_hash = compute_file_hash(file_bytes)
    filename = secure_filename(file.filename)

    # Check if same file hash exists = already signed
    if Document.query.filter_by(file_hash=file_hash).first():
        return jsonify({'status': 'already_signed', 'message': 'This exact document is already on blockchain!'}), 200
    
    # Check if same filename exists with different hash = modified/tampered
    existing_doc = Document.query.filter_by(filename=filename).first()
    if existing_doc:
        return jsonify({
            'status': 'hash_mismatch',
            'message': 'Document modified! Email token required to authorize update.',
            'original_hash': existing_doc.file_hash,
            'original_signer': existing_doc.owner.email if existing_doc.owner else 'unknown',
            'original_timestamp': existing_doc.signed_at.isoformat(),
            'original_block_hash': existing_doc.block_hash
        })

    student = User.query.filter_by(email=student_email).first() if student_email else current_user
    if not student:
        return jsonify({'error': 'Student not found'}), 404

    cert_pem, fingerprint, _ = extract_cert_from_request(request)
    if not fingerprint:
        with open(USER_CERT_PATH, 'rb') as f:
            cert_pem = f.read()
        fingerprint = get_cert_fingerprint(cert_pem)

    signature = sign_file_hash(file_hash, USER_KEY_PATH)

    save_path = os.path.join('uploads', filename)
    with open(save_path, 'wb') as f:
        f.write(file_bytes)

    block = blockchain.add_block(
        filename=filename, file_hash=file_hash,
        cert_fingerprint=fingerprint,
        email=student.email, signature=signature
    )

    expires_at = datetime.utcnow() + timedelta(days=expiry_days) if expiry_days > 0 else None

    doc = Document(
        filename=filename, original_name=file.filename,
        file_hash=file_hash, block_hash=block.hash,
        block_index=block.index, cert_fingerprint=fingerprint,
        signature=signature, doc_type=doc_type,
        user_id=student.id, expires_at=expires_at
    )
    db.session.add(doc)
    db.session.commit()

    qr_path = generate_qr(doc.id, file_hash)
    doc.qr_code_path = qr_path
    db.session.commit()

    log_action('DOCUMENT_SIGNED', f'{doc_type}: {filename} for {student.email}')

    return jsonify({
        'status': 'signed',
        'message': 'Document signed and recorded on blockchain!',
        'block_hash': block.hash,
        'block_index': block.index,
        'file_hash': file_hash,
        'qr_code': qr_path,
        'timestamp': block.timestamp
    })

# ─────────────────────────────────────────────
# API: VERIFY DOCUMENT
# ─────────────────────────────────────────────

@app.route('/api/verify', methods=['POST'])
def verify_document():
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    file = request.files['file']
    file_bytes = file.read()
    file_hash = compute_file_hash(file_bytes)

    block = blockchain.query_by_hash(file_hash)
    doc = Document.query.filter_by(file_hash=file_hash).first()

    log_action('DOCUMENT_VERIFIED', f'Hash: {file_hash[:16]}...',
               user_id=current_user.id if current_user.is_authenticated else None)

    if block and doc:
        is_expired = doc.expires_at and datetime.utcnow() > doc.expires_at
        return jsonify({
            'status': 'authentic' if not is_expired else 'expired',
            'message': 'Document is AUTHENTIC and verified on blockchain!' if not is_expired else 'Document has EXPIRED!',
            'signer_email': block.email,
            'owner_name': doc.owner.full_name if doc.owner else 'Unknown',
            'reg_number': doc.owner.reg_number if doc.owner else 'N/A',
            'department': doc.owner.department if doc.owner else 'N/A',
            'doc_type': doc.doc_type,
            'cert_fingerprint': block.cert_fingerprint,
            'timestamp': block.timestamp,
            'block_hash': block.hash,
            'file_hash': file_hash,
            'expires_at': doc.expires_at.isoformat() if doc.expires_at else 'Never',
            'qr_code': doc.qr_code_path
        })
    # Check if filename exists on blockchain with different hash = TAMPERED
    uploaded_filename = None
    if 'file' in request.files:
        from werkzeug.utils import secure_filename
        uploaded_filename = secure_filename(request.files['file'].filename)
    
    existing = blockchain.query_by_filename(uploaded_filename) if uploaded_filename else []
    
    if existing:
        # File exists on blockchain but hash is different = TAMPERED
        original = existing[-1]
        return jsonify({
            'status': 'tampered',
            'message': 'WARNING: Document has been TAMPERED! File exists on blockchain but content has been modified.',
            'file_hash': file_hash,
            'original_hash': original.file_hash,
            'original_signer': original.email,
            'original_timestamp': original.timestamp
        })
    else:
        # File never registered = UNREGISTERED
        return jsonify({
            'status': 'unregistered',
            'message': 'Document is UNREGISTERED. This file has never been signed or recorded on blockchain.',
            'file_hash': file_hash
        })

# ─────────────────────────────────────────────
# API: REVOKE DOCUMENT
# ─────────────────────────────────────────────

@app.route('/api/revoke/<int:doc_id>', methods=['POST'])
@login_required
def revoke_document(doc_id):
    if current_user.role != 'admin':
        return jsonify({'error': 'Admin only'}), 403
    doc = Document.query.get_or_404(doc_id)
    doc.status = 'revoked'
    db.session.commit()
    log_action('DOCUMENT_REVOKED', f'Doc ID {doc_id}: {doc.filename}')
    return jsonify({'success': True, 'message': 'Document revoked'})

# ─────────────────────────────────────────────
# API: REQUEST TOKEN
# ─────────────────────────────────────────────

@app.route('/api/request-token', methods=['POST'])
@login_required
def request_update_token():
    data = request.json or {}
    # Token always goes to ADMIN only - security feature!
    requested_for = data.get('email', current_user.email).strip()
    # Send to docproject email for demo
    ok, token = generate_token('docproject098@gmail.com')
    log_action('TOKEN_REQUESTED', f'Token requested for {requested_for}')
    return jsonify({
        'status': 'token_sent', 
        'message': f'Token sent to docproject098@gmail.com',
        'dev_token': token
    })

# ─────────────────────────────────────────────
# API: AUDIT LOGS
# ─────────────────────────────────────────────

@app.route('/api/audit-logs')
@login_required
def get_audit_logs():
    if current_user.role != 'admin':
        return jsonify({'error': 'Admin only'}), 403
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(50).all()
    return jsonify([l.to_dict() for l in logs])

# ─────────────────────────────────────────────
# API: CHAIN STATUS
# ─────────────────────────────────────────────

@app.route('/api/chain-status')
def chain_status():
    valid = blockchain.is_chain_valid()
    return jsonify({
        'valid': valid,
        'length': len(blockchain.chain),
        'status': 'Chain intact' if valid else 'WARNING: Chain tampered!'
    })

# ─────────────────────────────────────────────
# API: DASHBOARD STATS
# ─────────────────────────────────────────────

@app.route('/api/stats')
@login_required
def get_stats():
    return jsonify({
        'total_docs': Document.query.count(),
        'total_users': User.query.count(),
        'active_docs': Document.query.filter_by(status='active').count(),
        'revoked_docs': Document.query.filter_by(status='revoked').count(),
        'chain_length': len(blockchain.chain),
        'chain_valid': blockchain.is_chain_valid()
    })

# ─────────────────────────────────────────────
# API: MY DOCUMENTS (Student)
# ─────────────────────────────────────────────

@app.route('/api/my-documents')
@login_required
def my_documents():
    docs = Document.query.filter_by(user_id=current_user.id).all()
    return jsonify([d.to_dict() for d in docs])

# ─────────────────────────────────────────────
# SEARCH
# ─────────────────────────────────────────────

@app.route('/api/search')
@login_required
def search_documents():
    q = request.args.get('q', '').strip()
    if q:
        docs = Document.query.join(User).filter(
            db.or_(
                Document.original_name.contains(q),
                Document.file_hash.contains(q),
                Document.doc_type.contains(q),
                User.email.contains(q),
                User.full_name.contains(q),
                User.reg_number.contains(q)
            )
        ).all()
    else:
        docs = Document.query.all()
    #unused
        docs = Document.query.all()
    return jsonify([d.to_dict() for d in docs])

# ─────────────────────────────────────────────
# DATABASE INIT + ADMIN CREATE
# ─────────────────────────────────────────────

def create_admin():
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(email='admin@university.edu').first():
            admin = User(
                full_name='System Administrator',
                email='admin@university.edu',
                role='admin',
                department='IT Department'
            )
            admin.set_password('Admin@123')
            db.session.add(admin)
            db.session.commit()
            print('✅ Admin created: admin@university.edu / Admin@123')

# ─────────────────────────────────────────────
# RUN
# ─────────────────────────────────────────────

@app.route('/api/update', methods=['POST'])
@login_required
def update_document():
    if current_user.role != 'admin':
        return jsonify({'error': 'Admin only'}), 403
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    file = request.files['file']
    email = request.form.get('email', '').strip()
    token = request.form.get('token', '').strip()
    if not all([file, email, token]):
        return jsonify({'error': 'File, email, and token required'}), 400
    valid, msg = verify_token('docproject098@gmail.com', token)
    if not valid:
        return jsonify({'status': 'tampering_detected', 'message': f'Token failed: {msg}'}), 403
    file_bytes = file.read()
    file_hash = compute_file_hash(file_bytes)
    filename = secure_filename(file.filename)
    existing = Document.query.filter_by(filename=filename).first()
    parent_hash = existing.block_hash if existing else None
    cert_pem, fingerprint, _ = extract_cert_from_request(request)
    if not fingerprint:
        with open(USER_CERT_PATH, 'rb') as f2:
            cert_pem = f2.read()
        fingerprint = get_cert_fingerprint(cert_pem)
    signature = sign_file_hash(file_hash, USER_KEY_PATH)
    save_path = os.path.join('uploads', filename)
    with open(save_path, 'wb') as f2:
        f2.write(file_bytes)
    block = blockchain.add_block(
        filename=filename, file_hash=file_hash,
        cert_fingerprint=fingerprint, email=email,
        signature=signature, parent_hash=parent_hash
    )
    if existing:
        existing.file_hash = file_hash
        existing.block_hash = block.hash
        existing.block_index = block.index
        existing.signed_at = datetime.utcnow()
    else:
        doc = Document(
            filename=filename, original_name=file.filename,
            file_hash=file_hash, block_hash=block.hash,
            block_index=block.index, cert_fingerprint=fingerprint,
            signature=signature, doc_type='general',
            user_id=current_user.id
        )
        db.session.add(doc)
    db.session.commit()
    log_action('DOCUMENT_UPDATED', f'Updated: {filename}')
    return jsonify({
        'status': 'updated',
        'message': 'Document updated on blockchain!',
        'block_hash': block.hash,
        'block_index': block.index,
        'parent_hash': parent_hash,
        'timestamp': block.timestamp
    })

# Auto-init for gunicorn

create_admin()

if __name__ == '__main__':
    create_admin()




    print('🚀 UniVerify running on https://uliyach45-univerify.hf.space')
    print('👤 Admin: admin@university.edu | Password: Admin@123')
    app.run(host="0.0.0.0", port=5000, debug=False)
