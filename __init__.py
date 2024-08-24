#! /usr/bin/env python

from flask import Flask, render_template, flash, request, url_for, redirect, session, send_from_directory, send_file
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from pytz import timezone
from functools import wraps
import os, re
import OpenSSL
from cryptography.fernet import Fernet
import subprocess
import yaml

SCRIPT_PATH = os.path.dirname(os.path.abspath( __file__ ))
try:
    with open(SCRIPT_PATH + "/local.yml", 'r') as ymlfile:
        cfg = yaml.load(ymlfile)
except:
    print "Error: No local config present (local.yml)\n"
    quit()

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://%s:%s@%s/%s' % (cfg['mysql']['user'], cfg['mysql']['passwd'], cfg['mysql']['host'], cfg['mysql']['db'])
db = SQLAlchemy(app)
app.secret_key = cfg['appkeys']['flasksecret']
cipher_key = cfg['appkeys']['cipherkey']
cipher_suite = Fernet(cipher_key)

APP_ROOT = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(APP_ROOT, 'pfxfiles/')

class Certificates(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    domain = db.Column(db.String(250))
    key = db.Column(db.Text(10000))
    csr = db.Column(db.Text(10000))
    crt = db.Column(db.Text(10000))
    intermediate = db.Column(db.Text(10000))
    country = db.Column(db.String(50))
    state = db.Column(db.String(100))
    city = db.Column(db.String(250))
    organization = db.Column(db.String(250))
    organizational_unit = db.Column(db.String(250))
    email_address = db.Column(db.String(250))
    date_generated = db.Column(db.String(250))
    date_certstarts = db.Column(db.String(250))
    date_certexpires = db.Column(db.String(250))
    issuer = db.Column(db.String(250))

    def __init__(self, domain, key, csr, crt, intermediate, country, state, city, organization, organizational_unit, email_address, date_generated, date_certstarts, date_certexpires, issuer):
        self.domain = domain
        self.key = key
        self.csr = csr
        self.crt = crt
        self.intermediate = intermediate
        self.country = country
        self.state = state
        self.city = city
        self.organization = organization
        self.organizational_unit = organizational_unit
        self.email_address = email_address
        self.date_generated = date_generated
        self.date_certstarts = date_certstarts
        self.date_certexpires = date_certexpires
        self.issuer = issuer

class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100))
    password = db.Column(db.String(300))

    def __init__(self, username, password):
        self.username = username
        self.password = password

db.create_all()

def login_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            return redirect(url_for('login'))
    return wrap

def prettycert(cert):
    prettycert=''
    for line in cert.splitlines():
        prettycert = prettycert + line.strip() + '\n'
    return prettycert


def check_associate_cert_with_private_key(cert, private_key):
    try:
        private_key_obj = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, private_key)
    except OpenSSL.crypto.Error:
        raise Exception('private key is not correct: %s' % private_key)
    try:
        cert_obj = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
    except OpenSSL.crypto.Error:
        raise Exception('certificate is not correct: %s' % cert)
    context = OpenSSL.SSL.Context(OpenSSL.SSL.TLSv1_METHOD)
    context.use_privatekey(private_key_obj)
    context.use_certificate(cert_obj)
    try:
        context.check_privatekey()
        return True
    except OpenSSL.SSL.Error:
        return False

def create_pfx(cert, key, intermediate, filename):
    try:
        private_key_obj = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, key)
    except OpenSSL.crypto.Error:
        raise Exception('private key is not correct: %s' % key)
    try:
        cert_obj = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
    except OpenSSL.crypto.Error:
        raise Exception('certificate is not correct: %s' % cert)
    try:
        intermediate_obj = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, intermediate)
    except OpenSSL.crypto.Error:
        raise Exception('intermediate is not correct: %s' % intermediate)

    pfx = OpenSSL.crypto.PKCS12Type()
    pfx.set_privatekey(private_key_obj)
    pfx.set_certificate(cert_obj)
    pfx.set_ca_certificates([intermediate_obj])
    pfxdata = pfx.export(passphrase=None)



    with open(UPLOAD_FOLDER + filename, 'wb') as pfxfile:
        pfxfile.write(pfxdata)
    return True


def create_csr(common_name, country, state, city,
               organization, organizational_unit,
               email_address):

    key = OpenSSL.crypto.PKey()
    key.generate_key(OpenSSL.crypto.TYPE_RSA, 2048)

    req = OpenSSL.crypto.X509Req()
    req.get_subject().CN = common_name
    if country != '':
        req.get_subject().C = country
    if state != '':
        req.get_subject().ST = state
    if city != '':
        req.get_subject().L = city
    if organization != '':
        req.get_subject().O = organization
    if organizational_unit != '':
        req.get_subject().OU = organizational_unit
    if email_address != '':
        req.get_subject().emailAddress = email_address

    req.set_pubkey(key)
    req.sign(key, 'sha256')

    private_key = OpenSSL.crypto.dump_privatekey(
        OpenSSL.crypto.FILETYPE_PEM, key)

    csr = OpenSSL.crypto.dump_certificate_request(
               OpenSSL.crypto.FILETYPE_PEM, req)

    return private_key, csr

def read_csr(supplied_csr):
    req = OpenSSL.crypto.load_certificate_request(OpenSSL.crypto.FILETYPE_PEM, supplied_csr)
    key = req.get_pubkey()
    key_type = 'RSA' if key.type() == OpenSSL.crypto.TYPE_RSA else 'DSA'
    subject = req.get_subject()
    components = dict(subject.get_components())
    return components

def read_crt(supplied_crt):
    cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, supplied_crt)
    subject = cert.get_subject()
    components = dict(subject.get_components())
    notAfter = datetime.strptime(cert.get_notAfter(),"%Y%m%d%H%M%SZ")
    notBefore = datetime.strptime(cert.get_notBefore(),"%Y%m%d%H%M%SZ")
    issuer = cert.get_issuer()
    return components, issuer.O, notAfter, notBefore

@app.route('/')
@login_required
def homepage():
    return render_template("index.html", pageType="home")

@app.route('/create')
@login_required
def create():
    return render_template("gencsr.html")

@app.route('/verify', methods=['GET','POST'])
@login_required
def verify():
    certinfo = []
    domain = request.form['domain']
    process = subprocess.Popen(["sslyze", "--certinfo", domain], stdout=subprocess.PIPE)
    info, err = process.communicate()
    readswitch=False
    for line in info.splitlines():
        if 'CHECKING HOST(S) AVAILABILITY' in line:
            readswitch=True
        if readswitch:
            certinfo.append(line)
    return render_template("verify.html", certinfo=certinfo)

@app.route('/results', methods=['GET','POST'])
@login_required
def results():
    domain = request.form['domain']
    certid = []
    date_generated = []
    organization = []
    res_domain = []
    for instance in reversed(db.session.query(Certificates).all()):
        if domain in instance.domain:
            res_domain.append(instance.domain)
            date_generated.append(instance.date_generated)
            organization.append(instance.organization)
            certid.append(instance.id)
    results = zip(certid, res_domain, date_generated, organization)
    return render_template("results.html", results=results)


@app.route('/generate', methods=['GET','POST'])
@login_required
def generate():
    domain = request.form['common_name']
    Cust_CSR = create_csr(request.form['common_name'], request.form['country'], request.form['state'], request.form['city'], request.form['organization'], request.form['organizational_unit'], request.form['email_address'])
    pdt=datetime.now(timezone('US/Pacific'))
    time=pdt.strftime('%Y-%m-%d')
    add_cert = Certificates(key=Cust_CSR[0],
                            csr=Cust_CSR[1],
                            crt='None',
                            intermediate='None',
                            domain=request.form['common_name'],
                            country=request.form['country'],
                            state=request.form['state'],
                            city=request.form['city'],
                            organization=request.form['organization'],
                            organizational_unit=request.form['organizational_unit'],
                            email_address=request.form['email_address'],
                            date_generated=time,
                            date_certstarts='None',
                            date_certexpires='None',
                            issuer='None'
                            )
    db.session.add(add_cert)
    db.session.commit()
    certid = add_cert.id
    return redirect(url_for('display', certid=certid))

@app.route('/display', methods=['GET','POST'])
@login_required
def display():
    certid = request.args['certid']
    cert = db.session.query(Certificates).filter_by(id=certid).first()
    return render_template("display.html", cert=cert)

@app.route('/genpfx/<filename>', methods=['GET','POST'])
@login_required
def genpfx(filename):
    certid = request.form['certid']
    cert = db.session.query(Certificates).filter_by(id=certid).first()
    create_pfx(cert.crt, cert.key, cert.intermediate, filename)
    return send_file(UPLOAD_FOLDER + filename)

@app.route('/addcrt', methods=['GET','POST'])
@login_required
def addcrt():
    certid=request.form['certid']
    crt=request.form['certificate']
    certerror = "None"

    foundcert = db.session.query(Certificates).filter_by(id=certid).first()
    certkey = foundcert.key
    try:
        if check_associate_cert_with_private_key(crt, certkey):
            components, issuer, notAfter, notBefore = read_crt(crt)
            foundcert.issuer = issuer
            foundcert.date_certstarts = notBefore
            foundcert.date_certexpires = notAfter
            foundcert.crt = prettycert(crt)
            db.session.commit()
        else:
            flash('Provided certificate does not match key!')
    except:
        flash('Provided certificate does not match key!')
    return redirect(url_for('display', certid=certid))

@app.route('/addintermediate', methods=['GET','POST'])
@login_required
def addintermediate():
    certid=request.form['certid']
    foundcert = db.session.query(Certificates).filter_by(id=certid).first()
    foundcert.intermediate = prettycert(request.form['intermediate'])
    db.session.commit()
    return redirect(url_for('display', certid=certid))

@app.route('/storecomponents', methods=['GET','POST'])
@login_required
def storecomponents():
    pdt=datetime.now(timezone('US/Pacific'))
    time=pdt.strftime('%Y-%m-%d')
    if check_associate_cert_with_private_key(request.form['certificate'], request.form['key']):
        components, issuer, notAfter, notBefore = read_crt(request.form['certificate'])
        add_cert = Certificates(key=prettycert(request.form['key']),
                                csr=prettycert(request.form['csr']),
                                crt=prettycert(request.form['certificate']),
                                intermediate='None',
                                domain=request.form['common_name'],
                                country=request.form['country'],
                                state=request.form['state'],
                                city=request.form['city'],
                                organization=request.form['organization'],
                                organizational_unit=request.form['organizational_unit'],
                                email_address=request.form['email_address'],
                                date_generated=time,
                                date_certstarts=notBefore,
                                date_certexpires=notAfter,
                                issuer=issuer
                                )
        db.session.add(add_cert)
        db.session.commit()
        certid = add_cert.id
    else:
        flash('ERROR: Not stored. Provided certificate does not match key!')
        return redirect(url_for('add'))
    return redirect(url_for('display', certid=certid))

@app.route('/add', methods=['GET','POST'])
@login_required
def add():
    return render_template("add.html")

@app.route('/addfromcrt', methods=['GET','POST'])
@login_required
def addfromcrt():
    components="None"
    certificate=""
    if request.method == "POST":
        certificate=request.form['suppliedcrt']
        components, issuer, notAfter, notBefore = read_crt(certificate)
    return render_template("addfromcrt.html", components=components, certificate=certificate)

@app.route('/addfromcsr', methods=['GET','POST'])
@login_required
def addfromcsr():
    components="None"
    csr=""
    if request.method == "POST":
        csr=request.form['csr']
        components=read_csr(csr)
    return render_template("addfromcsr.html", components=components, csr=csr)

@app.route('/decode', methods=['GET','POST'])
@login_required
def decode():
    components="None"
    if request.method == "POST":
        components=read_csr(request.form['suppliedcsr'])
    return render_template("decode.html", components=components)

@app.route("/login", methods=['GET','POST'])
def login():
    if request.method == "POST":
        user=request.form['user']
        password=request.form['password']

        for instance in db.session.query(Users).order_by(Users.id):
            if user == instance.username:
                decrypted_pass = cipher_suite.decrypt(str(instance.password))
                if password == decrypted_pass:
                    session['logged_in'] = True
                    session['username'] = user
                    return redirect(url_for('homepage'))
    return render_template("login.html")

@app.route("/add_user")
#@login_required
def add_user():
    return render_template("add_user.html")

@app.route('/verify_user', methods=['GET','POST'])
#@login_required
def verify_user():
    is_success = "No"
    user=request.form['user']
    password=request.form['password']

    # for instance in db.session.query(Users).order_by(Users.id):
    #     print instance.username, instance.password
    for instance in db.session.query(Users).order_by(Users.id):
        if user in instance.username:
            is_success = "User already exists."
            break
    if is_success == "No":
        bytepass = password.encode('utf-8')
        adduser = Users(user, cipher_suite.encrypt(bytepass))
        db.session.add(adduser)
        db.session.commit()
        is_success = "User Added"
        session['logged_in'] = True
        session['username'] = user
        return redirect(url_for('homepage'))
    return is_success

@app.route('/delete_cert', methods=['GET','POST'])
@login_required
def delete_cert():
    certid = request.args['certid']
    Certificates.query.filter_by(id=certid).delete()
    db.session.commit()
    return redirect(url_for('homepage'))

@app.route("/logout")
@login_required
def logout():
    session.clear()
    return redirect(url_for('homepage'))

if __name__ == '__main__':
    app.debug=True
    app.run()
