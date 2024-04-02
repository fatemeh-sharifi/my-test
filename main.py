from flask import Flask, render_template, request, redirect, url_for, session,make_response,flash,current_app
from flask_mysqldb import MySQL
import MySQLdb.cursors
import re
import datetime
from datetime import date,timedelta
import time
import numpy
from werkzeug.utils import secure_filename
import os
import jdatetime
from server_tcp import *
from threading import Thread
from flask_cors import CORS
import csv
import requests
import uuid
import smtplib
import ssl
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import threading
from collections import defaultdict
from persiantools.jdatetime import JalaliDate
from math import ceil
# import sympy as sp



UPLOAD_FOLDER = 'static/assets/images/'


app = Flask(__name__)

# Change this to your secret key (can be anything, it's for extra protection)
app.secret_key = 'your secret key'

# Enter your database connection details below
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'FTC@cloud'
app.config['MYSQL_PASSWORD'] = 'AVoMGCPDL*PHM2Pe'
app.config['MYSQL_DB'] = 'fanavaran'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024


# app.config['MAIL_SERVER'] = 'smtp.gmail.com'
# app.config['MAIL_PORT'] = 587
# app.config['MAIL_USE_TLS'] = True
# app.config['MAIL_USERNAME'] = 'fsharifi8859@gmail.com'
# app.config['MAIL_PASSWORD'] = 'ezzr whvg jhai dsci '
# Intialize MySQL
mysql = MySQL(app)
# mail = Mail(app)

loginAttempts = {}
attemptTime = {}
blockTime = 30 * 60
maxFailed = 5

@app.before_request
def make_session_permanent():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(minutes = 5 * 60)

@app.route('/', methods = ['POST','GET'])
def begin_page():
    return render_template('begin_page.html')

def blockIp(ip):
    blockT = time.time() + blockTime
    attemptTime[ip] = blockT

def isIpBlocked(ip):
    return attemptTime[ip] > time.time()

@app.route('/smart_farming_login', methods=['GET', 'POST'])
def smart_farming_login():
    if 'loggedin' in session:
        # User is loggedin show them the home page
        return redirect(url_for('manage_device'))
    ipAddr = request.remote_addr
    msg = ''
    # Check if "username" and "password" POST requests exist (user submitted form)
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
        
        if ipAddr in attemptTime and isIpBlocked(ipAddr):
            msg = str(ceil((attemptTime[ipAddr] - time.time())/60)) + ' زمان تا پایان محدودیت مانده است.بعدا تلاش کنید.'
            # return render_template('login.html', msg=msg)
        else:
            # Create variables for easy access
            username = request.form['username']
            password = request.form['password']
            # Check if account exists using MySQL
            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            cursor.execute('SELECT * FROM accounts WHERE username = %s AND password = SHA2(%s, 256)', (username, password,))
            # Fetch one record and return result
            account = cursor.fetchone()
            # If account exists in user table in out database
            if account:
                # Create session data, we can access this data in other routes
                session['loggedin'] = True
                session['id'] = account['id']
                session['username'] = account['username']
                session['first_name'] = account['first_name']
                session['last_name'] = account['last_name']
                
                if ipAddr in loginAttempts:
                    del loginAttempts[ipAddr]
                if ipAddr in attemptTime:
                    del attemptTime[ipAddr]
                # Redirect to home page
                return redirect(url_for('manage_device'))
            else:
                loginAttempts[ipAddr] = loginAttempts.get(ipAddr,0)+1
                if loginAttempts[ipAddr] >= maxFailed:
                    blockIp(ipAddr)
                    msg = 'تعداد تلاش شما از حد مجاز رد شده است. 30 دقیقه دیگر تلاش کنید'
                else:
                # Account doesnt exist or username/password incorrect
                    msg = 'نام کاربری یا رمز عبور اشتباه هست'
    # Show the login form with message (if any)
    return render_template('login.html', msg=msg)




# http://localhost:5000/python/logout - this will be the logout page
@app.route('/logout')
def logout():
    # Remove session data, this will log the user out
   session.pop('loggedin', None)
   session.pop('id', None)
   session.pop('username', None)
   session.pop('first_name', None)
   session.pop('last_name', None)
   # Redirect to login page
   return redirect(url_for('smart_farming_login'))



# http://localhost:5000/pythinlogin/register - this will be the registration page, we need to use both GET and POST requests
@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'loggedin' in session:
        # User is loggedin show them the home page
        return redirect(url_for('manage_device'))

    msg = ''
    # This file was generated by The-Big-Username-Blocklist VERSION=v2.0.1 (at 2021-02-13 10:53:03.852225)
    block_list = ['.git', '.htaccess', '.htpasswd', '.well-known', '400', '401', '403', '404', '405', '406', '407', '408', '409', '410', '411', '412', '413', '414', '415', '416', '417', '421', '422', '423', '424', '426', '428', '429', '431', '500', '501', '502', '503', '504', '505', '506', '507', '508', '509', '510', '511', '_domainkey', 'about', 'about-us', 'abuse', 'access', 'account', 'accounts','user', 'ad', 'add', 'admin', 'administration', 'administrator', 'ads', 'ads.txt', 'advertise', 'advertising', 'aes128-ctr', 'aes128-gcm', 'aes192-ctr', 'aes256-ctr', 'aes256-gcm', 'affiliate', 'affiliates', 'ajax', 'alert', 'alerts', 'alpha', 'amp', 'analytics', 'api', 'app', 'app-ads.txt', 'apps', 'asc', 'assets', 'atom', 'auth', 'authentication', 'authorize', 'autoconfig', 'autodiscover', 'avatar', 'backup', 'banner', 'banners', 'bbs', 'beta', 'billing', 'billings', 'blog', 'blogs', 'board', 'bookmark', 'bookmarks', 'broadcasthost', 'business', 'buy', 'cache', 'calendar', 'campaign', 'captcha', 'careers', 'cart', 'cas', 'categories', 'category', 'cdn', 'cgi', 'cgi-bin', 'chacha20-poly1305', 'change', 'channel', 'channels', 'chart', 'chat', 'checkout', 'clear', 'client', 'close', 'cloud', 'cms', 'com', 'comment', 'comments', 'community', 'compare', 'compose', 'config', 'connect', 'contact', 'contest', 'cookies', 'copy', 'copyright', 'count', 'cp', 'cpanel', 'create', 'crossdomain.xml', 'css', 'curve25519-sha256', 'customer', 'customers', 'customize', 'dashboard', 'db', 'deals', 'debug', 'delete', 'desc', 'destroy', 'dev', 'developer', 'developers', 'diffie-hellman-group-exchange-sha256', 'diffie-hellman-group14-sha1', 'disconnect', 'discuss', 'dns', 'dns0', 'dns1', 'dns2', 'dns3', 'dns4', 'docs', 'documentation', 'domain', 'download', 'downloads', 'downvote', 'draft', 'drop', 'ecdh-sha2-nistp256', 'ecdh-sha2-nistp384', 'ecdh-sha2-nistp521', 'edit', 'editor', 'email', 'enterprise', 'error', 'errors', 'event', 'events', 'example', 'exception', 'exit', 'explore', 'export', 'extensions', 'false', 'family', 'faq', 'faqs', 'favicon.ico', 'features', 'feed', 'feedback', 'feeds', 'file', 'files', 'filter', 'follow', 'follower', 'followers', 'following', 'fonts', 'forgot', 'forgot-password', 'forgotpassword', 'form', 'forms', 'forum', 'forums', 'friend', 'friends', 'ftp', 'get', 'git', 'go', 'graphql', 'group', 'groups', 'guest', 'guidelines', 'guides', 'head', 'header', 'help', 'hide', 'hmac-sha', 'hmac-sha1', 'hmac-sha1-etm', 'hmac-sha2-256', 'hmac-sha2-256-etm', 'hmac-sha2-512', 'hmac-sha2-512-etm', 'home', 'host', 'hosting', 'hostmaster', 'htpasswd', 'http', 'httpd', 'https', 'humans.txt', 'icons', 'images', 'imap', 'img', 'import', 'index', 'info', 'insert', 'investors', 'invitations', 'invite', 'invites', 'invoice', 'is', 'isatap', 'issues', 'it', 'jobs', 'join', 'js', 'json', 'keybase.txt', 'learn', 'legal', 'license', 'licensing', 'like', 'limit', 'live', 'load', 'local', 'localdomain', 'localhost', 'lock', 'login', 'logout', 'lost-password', 'm', 'mail', 'mail0', 'mail1', 'mail2', 'mail3', 'mail4', 'mail5', 'mail6', 'mail7', 'mail8', 'mail9', 'mailer-daemon', 'mailerdaemon', 'map', 'marketing', 'marketplace', 'master', 'me', 'media', 'member', 'members', 'message', 'messages', 'metrics', 'mis', 'mobile', 'moderator', 'modify', 'more', 'mx', 'mx1', 'my', 'net', 'network', 'new', 'news', 'newsletter', 'newsletters', 'next', 'nil', 'no-reply', 'nobody', 'noc', 'none', 'noreply', 'notification', 'notifications', 'ns', 'ns0', 'ns1', 'ns2', 'ns3', 'ns4', 'ns5', 'ns6', 'ns7', 'ns8', 'ns9', 'null', 'oauth', 'oauth2', 'offer', 'offers', 'online', 'openid', 'order', 'orders', 'overview', 'owa', 'owner', 'page', 'pages', 'partners', 'passwd', 'password', 'pay', 'payment', 'payments', 'paypal', 'photo', 'photos', 'pixel', 'plans', 'plugins', 'policies', 'policy', 'pop', 'pop3', 'popular', 'portal', 'portfolio', 'post', 'postfix', 'postmaster', 'poweruser', 'preferences', 'premium', 'press', 'previous', 'pricing', 'print', 'privacy', 'privacy-policy', 'private', 'prod', 'product', 'production', 'profile', 'profiles', 'project', 'projects', 'promo', 'public', 'purchase', 'put', 'quota', 'redirect', 'reduce', 'refund', 'refunds', 'register', 'registration', 'remove', 'replies', 'reply', 'report', 'request', 'request-password', 'reset', 'reset-password', 'response', 'return', 'returns', 'review', 'reviews', 'robots.txt', 'root', 'rootuser', 'rsa-sha2-2', 'rsa-sha2-512', 'rss', 'rules', 'sales', 'save', 'script', 'sdk', 'search', 'secure', 'security', 'select', 'services', 'session', 'sessions', 'settings', 'setup', 'share', 'shift', 'shop', 'signin', 'signup', 'site', 'sitemap', 'sites', 'smtp', 'sort', 'source', 'sql', 'ssh', 'ssh-rsa', 'ssl', 'ssladmin', 'ssladministrator', 'sslwebmaster', 'stage', 'staging', 'stat', 'static', 'statistics', 'stats', 'status', 'store', 'style', 'styles', 'stylesheet', 'stylesheets', 'subdomain', 'subscribe', 'sudo', 'super', 'superuser', 'support', 'survey', 'sync', 'sysadmin', 'sysadmin', 'system', 'tablet', 'tag', 'tags', 'team', 'telnet', 'terms', 'terms-of-use', 'FTC-admin', 'testimonials', 'theme', 'themes', 'today', 'tools', 'topic', 'topics', 'tour', 'training', 'translate', 'translations', 'trending', 'trial', 'true', 'umac-128', 'umac-128-etm', 'umac-64', 'umac-64-etm', 'undefined', 'unfollow', 'unlike', 'unsubscribe', 'update', 'upgrade', 'usenet', 'user', 'username', 'users', 'uucp', 'var', 'verify', 'video', 'view', 'void', 'vote', 'vpn', 'webmail', 'webmaster', 'website', 'widget', 'widgets', 'wiki', 'wpad', 'write', 'www', 'www-data', 'www1', 'www2', 'www3', 'www4', 'you', 'yourname', 'yourusername', 'zlib']
    # Check if "username", "password" and "email" POST requests exist (user submitted form)
    if request.method == 'POST' and 'firstname' in request.form and 'lastname' in request.form and 'username' in request.form and 'phone' in request.form and 'password' in request.form and 'mail' in request.form:
        # Create variables for easy access
        firstname = request.form['firstname']
        lastname = request.form['lastname']
        username = request.form['username']
        phone = request.form['phone']
        password = request.form['password']
        newmail = request.form['mail']
        # Check if account exists using MySQL
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE username = %s', (username,))
        account = cursor.fetchone()
        # If account exists show error and validation checks
        if account:
            cursor.close()
            msg = 'حساب کاربری از قبل وجود دارد !'
        elif not re.match(r'[A-Za-z0-9]+', username):
            cursor.close()
            msg = 'نام کاربری فقط می تواند حاوی حروف و اعداد انگلیسی باشد !'
        elif username in block_list:
            cursor.close()
            msg = 'نام کاربری مجاز نمی باشد !'
        elif not firstname or not lastname or not username or not phone or not password or not newmail:
            cursor.close()
            msg = 'موارد را تکمیل کنید !'
        else:
            # Account doesnt exists and the form data is valid, now insert new account into user table
            cursor.execute('INSERT INTO accounts (first_name, last_name, username, phone_number, mail, password) VALUES (%s, %s, %s, %s, %s, SHA2(%s, 256))', (firstname, lastname, username, phone, newmail, password,))            
            mysql.connection.commit()
            cursor.close()
            msg = 'حساب کاربری با موفقیت ایجاد شد !'
            return render_template('login.html', msg=msg)
    elif request.method == 'POST':
        # Form is empty... (no POST data)
        cursor.close()
        msg = 'لطفا موارد زیر را پر کنید !'
    # Show registration form with message (if any)
    return render_template('register.html', msg=msg)




@app.route('/index')
def index():
    # Check if user is loggedin
    if 'loggedin' in session:
        # User is loggedin show them the home page
        return redirect(url_for('manage_device'))
    # User is not loggedin redirect to login page
    return redirect(url_for('smart_farming_login'))
    


@app.route('/add_device', methods=['GET', 'POST'])
def add_device():
    # Check if user is loggedin
    if 'loggedin' in session:
        msg =''
        if request.method == 'POST' and 'serial_number' in request.form and 'password_device' in request.form :
            # Create variables for easy access
            user_model_name = request.form['user_model_name']
            serial_number = request.form['serial_number']
            password_device = request.form['password_device']
            # Check if account exists using MySQL
            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            cursor.execute('SELECT * FROM device WHERE serial_number = %s AND password_device = %s', (serial_number, password_device,))
            # Fetch one record and return result
            device = cursor.fetchone()
            cursor.execute('SELECT * FROM user_device WHERE serial_number  = %s', (serial_number,))
            serial_device = cursor.fetchone()

            cursor.execute('SELECT * FROM user_device WHERE serial_number  = %s and id= %s', (serial_number,session['id']))
            check_device = cursor.fetchone()
            
            if device:
                if not serial_device:
                    sensorNames = ""
                    senarioData= ""
                    pinNum = 0
                    sensorNum = 0
                    if device['device_type'] == "eshtad":
                        sensorNames = "دما&رطوبت&روشنایی&دما&رطوبت&دما&رطوبت"
                        sensorNum = 7
                    cursor.execute('INSERT INTO user_device (id_user, serial_number, con_num, senario,pinNumber,sensor_number,sensor_titles	) VALUES (%s, %s, 0, %s,%s,%s,%s)', (session['id'], serial_number,senarioData,pinNum,sensorNum,sensorNames))                    
                    cursor.execute('UPDATE device SET user_model_name = %s WHERE device.serial_number = %s ', (user_model_name, serial_number))
                    mysql.connection.commit()
                    cursor.close()
                    msg ='دستگاه با موفقیت اضافه شد'
                    return render_template('add_device.html', msg=msg,name=session['first_name'])
                elif check_device:
                    cursor.close()
                    msg ='دستگاه از قبل وجود دارد!'
                    return render_template('add_device.html', msg=msg,name=session['first_name'])
                cursor.close()
                msg ='مالک دستگاه شخصی دیگر است، در صورت ارسال دوباره مفادیر با پیگرد قانونی مواجه خواهید شد!!!!'
                return render_template('add_device.html', msg=msg,name=session['first_name'])
            else:
                cursor.close()
                msg = 'سریال دستگاه یا رمز دستگاه اشتباه هست'
        return render_template('add_device.html', msg=msg,name=session['first_name'])
    # User is not loggedin redirect to login page
    return redirect(url_for('smart_farming_login'))



@app.route('/manage_device')
def manage_device():
    # Check if user is loggedin
    if 'loggedin' in session:
        if session['username'] != "FTC-admin":
            msg=''
            final = ()
            final_date =()
            final_res =()
            con_dev=()
            count_date=0
            count = 0
            mycursor = mysql.connection.cursor()
            mycursor.execute("SELECT serial_number FROM user_device WHERE id_user = %s",(session['id'],))
            res = mycursor.fetchall()
            if res:
                res = numpy.array(res)
                count_device = res.size
                final = ()
                count = 0
                # get data from database in dict
                mycursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
                for i in range(count_device):
                    mycursor.execute("SELECT * FROM device where serial_number = %s",(res[count]))
                    natij = mycursor.fetchall()
                    final = final + natij
                    count = count + 1
                count = 0
                for i in range(count_device):
                    mycursor.execute("SELECT create_date FROM device WHERE serial_number = %s",(res[count]))
                    date = mycursor.fetchall()
                    dates = re.findall(r"\d+, \d+, \d+", str(date))
                    for date2 in dates:
                        year,month,day=date2.split(",")
                        shamsi ={'jdate': jdatetime.date.fromgregorian(day=int(day),month=int(month),year=int(year))}
                        shamsi =(shamsi,)
                        final_date = final_date + shamsi
                        count_date = count_date+1
                    count = count + 1
                count =0
                mycursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
                for i in range(count_device):
                    mycursor.execute("SELECT `con_num` FROM `user_device` WHERE `serial_number` = %s",(res[count]))
                    status_dev = mycursor.fetchall()
                    status_dev1 = re.search(r"\d", str(status_dev))
                    status_dev1 = status_dev1.group()
                    if status_dev1 == '0':
                        status_dev ={'dev_status': "آفلاین"}
                    else:
                        status_dev ={'dev_status': "آنلاین"}
                    status_dev = (status_dev,)
                    con_dev = con_dev + status_dev
                    count = count + 1
                mycursor.close()
                count =0
                for i in range(count_date):
                    n = final[count]
                    m = final_date[count]
                    v = con_dev[count]
                    n.update(m)
                    n.update(v)
                    n = (n,)
                    final_res = final_res + n
                    count = count+1
            else:
                final = ''
                msg = session['first_name'] +' '+ session['last_name'] +' '+ "شما هیچ دستگاهی اضافه نکردید"
            return render_template('manage_device.html',devices = final_res,first_last_name = session['first_name'] +' '+ session['last_name'],username = session['username'],msg = msg,name=session['first_name'])
        else:
            return redirect(url_for('admin_manage_device'))
    # User is not loggedin redirect to login page
    return redirect(url_for('smart_farming_login'))


@app.route('/admin_manage_device')
def admin_manage_device():
    # Check if user is loggedin
    if 'loggedin' in session:
        if session['username'] == "FTC-admin":
            final = ()
            final_date =()
            final_res =()
            con_dev=()
            count_date=0
            count = 0
            mycursor = mysql.connection.cursor()
            mycursor.execute("SELECT serial_number FROM device ")
            res = mycursor.fetchall()
            if res:
                res = numpy.array(res)
                count_device = res.size
                final = ()
                count = 0
                # get data from database in dict
                mycursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
                for i in range(count_device):
                    mycursor.execute("SELECT * FROM device where serial_number = %s",(res[count]))
                    natij = mycursor.fetchall()
                    final = final + natij
                    count = count + 1
                count = 0
                for i in range(count_device):
                    mycursor.execute("SELECT create_date FROM device WHERE serial_number = %s",(res[count]))
                    date = mycursor.fetchall()
                    dates = re.findall(r"\d+, \d+, \d+", str(date))
                    for date2 in dates:
                        year = date2[0:4]
                        month = date2[6:8]
                        day = date2[10:12]
                        shamsi ={'jdate': jdatetime.date.fromgregorian(day=int(day),month=int(month),year=int(year))}
                        shamsi =(shamsi,)
                        final_date = final_date + shamsi
                        count_date = count_date+1
                    count = count + 1
                count =0
                mycursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
                for i in range(count_device):
                    mycursor.execute("SELECT `con_num` FROM `user_device` WHERE `serial_number` = %s",(res[count]))
                    status_dev = mycursor.fetchall()
                    status_dev1 = re.search(r"\d", str(status_dev))
                    try:
                        status_dev1 = status_dev1.group()
                        if status_dev1 == '0':
                            status_dev ={'dev_status': "آفلاین"}
                        else:
                            status_dev ={'dev_status': "آنلاین"}
                    except:
                        status_dev ={'dev_status': "مالکی ندارد"}
                    status_dev = (status_dev,)
                    con_dev = con_dev + status_dev
                    count = count + 1
                mycursor.close()
                count =0
                for i in range(count_date):
                    n = final[count]
                    m = final_date[count]
                    v = con_dev[count]
                    n.update(m)
                    n.update(v)
                    n = (n,)
                    final_res = final_res + n
                    count = count+1
            # Show the profile page with account info
            return render_template('admin_manage_device.html',devices = final_res,first_last_name = session['first_name'] +' '+ session['last_name'],username = session['username'],name=session['first_name'])
        else:
            return redirect(url_for('not_found'))
    # User is not loggedin redirect to login page
    return redirect(url_for('smart_farming_login'))


@app.route('/device',methods=['GET', 'POST'])
def device():
    # Check if user is loggedin
    if 'loggedin' in session:
        if request.method == 'GET' :
            if session['username'] == "FTC-admin":
                return redirect(url_for('admin_manage_device'))
            return redirect(url_for('manage_device'))
        if request.method == 'POST':
            serial_num = request.form['dev_ser']
            name = request.form['dev_name']
            jdate = request.form['dev_jdate']
            shamsi = ''
            msg=''
            final_res = ''
            mycursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            mycursor.execute("SELECT `con_num` FROM `user_device` WHERE `serial_number` = %s",(serial_num,))
            status = mycursor.fetchall()
            status = re.search(r"\d", str(status))
            try:
                status = status.group()
                if status == '0':
                    status ="آفلاین"
                else:
                    status ="آنلاین"
            except:
                status ="مالکی ندارد"
            if session['username'] != "FTC-admin":
                mycursor = mysql.connection.cursor()
                mycursor.execute("SELECT serial_number FROM user_device WHERE id_user = %s",(session['id'],))
                res = mycursor.fetchall()
            else :
                res = 'admin'
            if res:
                final = ()
                final_date =()
                final_res =()
                count_date=0
                count = 0
                # get data from database in dict
                mycursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
                mycursor.execute("SELECT * FROM `device_log` WHERE serial_number = %s ORDER BY `device_log`.`date` DESC ,`device_log`.`time` DESC",(serial_num,))
                natij = mycursor.fetchall()
                final = final + natij
                dates = re.findall(r"\d+, \d+, \d+", str(natij))
                for date2 in dates:
                    year,month,day=date2.split(",")
                    shamsi ={'jdate': jdatetime.date.fromgregorian(day=int(day),month=int(month),year=int(year))}
                    shamsi =(shamsi,)
                    final_date = final_date + shamsi
                    count_date = count_date+1
                count =0
                for i in range(count_date):
                    n = final[count]
                    m = final_date[count]
                    n.update(m)
                    n = (n,)
                    final_res = final_res + n
                    count = count+1
                mycursor = mysql.connection.cursor()
                mycursor.execute("SELECT date FROM device_log  WHERE serial_number =  %s ORDER BY `device_log`.`date` DESC ,`device_log`.`time` DESC Limit 1",(serial_num,))
                date = mycursor.fetchall()
                if date:
                    dates = re.findall(r"\d+, \d+, \d+", str(date))
                    dates = str(dates)
                    year1,month1,day1 = dates[2:-2].split(',')
                    try:
                        shamsi =(jdatetime.date.fromgregorian(day=int(day1),month=int(month1),year=int(year1)))
                        shamsi = re.sub(r"-", '/', str(shamsi))
                        mycursor.execute("SELECT time FROM device_log  WHERE serial_number =  %s ORDER BY `device_log`.`date` DESC ,`device_log`.`time` DESC Limit 1",(serial_num,))
                        time = mycursor.fetchall()
                        mycursor.close()
                        time = re.search(r"\d+", str(time))
                        time = time.group()
                        seconds = int(time)
                        time = timedelta(seconds=seconds)
                        shamsi = str(time)+' - '+shamsi
                    except:
                        shamsi =session['first_name'] +' '+ session['last_name'] +' '+ "عزیز هیچ اطلاعاتی برای نمایش این دستگاه وجود ندارد"
                        msg = session['first_name'] +' '+ session['last_name'] +' '+ "عزیز هیچ اطلاعاتی برای نمایش این دستگاه وجود ندارد"
                else:
                    shamsi =session['first_name'] +' '+ session['last_name'] +' '+ "عزیز هیچ اطلاعاتی برای نمایش این دستگاه وجود ندارد"
                    msg = session['first_name'] +' '+ session['last_name'] +' '+ "عزیز هیچ اطلاعاتی برای نمایش این دستگاه وجود ندارد"
            else:
                mycursor.close()
                final = ''
                msg = session['first_name'] +' '+ session['last_name'] +' '+ "عزیز هیچ اطلاعاتی برای نمایش این دستگاه وجود ندارد"
            mycursor = mysql.connection.cursor()
            mycursor.execute('SELECT pin_stat FROM user_device WHERE `serial_number` = %s',(serial_num,))
            pin_stats = mycursor.fetchone()
            if pin_stats[0] is not None:
                stats = list(filter(None, pin_stats[0].split('&')))
            else:
                stats = []
            mycursor = mysql.connection.cursor()
            mycursor.execute('SELECT pin_logo FROM user_device WHERE `serial_number` = %s',(serial_num,))
            pin_logos = mycursor.fetchone()
            if pin_logos[0] is not None:
                logos = list(filter(None, pin_logos[0].split('&')))
            else:
                logos = []
            mycursor = mysql.connection.cursor()
            mycursor.execute('SELECT pinNumber FROM user_device WHERE `serial_number` = %s',(serial_num,))
            pinNum = mycursor.fetchone()
        return render_template('device.html',serial_number = serial_num,device_status = status,dev_name=name,dev_jdate=jdate,logs = final_res,last_date =shamsi,msg=msg,name=session['first_name'], pin_logo = logos,  pin = stats , pin_num = pinNum[0])
    # User is not loggedin redirect to login page
    return redirect(url_for('smart_farming_login'))


@app.route('/admin_list_user',methods=['GET', 'POST'])
def admin_list_user():
    # Check if user is loggedin
    if 'loggedin' in session:
        if session['username'] == "FTC-admin":
            msg=""
            if request.method == 'GET':
                mycursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
                mycursor.execute("SELECT * FROM accounts")
                res = mycursor.fetchall()
                return render_template('admin_list_user.html',accounts = res,first_last_name = session['first_name'] +' '+ session['last_name'],username = session['username'],msgs=msg)
            elif request.method == 'POST' and 'username' in request.form and 'password' in request.form:
                username = request.form['username']
                password = request.form['password']
                cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
                cursor.execute('UPDATE `accounts` SET `password`=MD5(%s) WHERE `username`= %s', (password, username,))
                cursor.connection.commit()
                cursor.close()
                msg = "با موفقیت انجام شد."
                mycursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
                mycursor.execute("SELECT * FROM accounts")
                res = mycursor.fetchall()
                mycursor.close()
                return render_template('admin_list_user.html',accounts = res,first_last_name = session['first_name'] +' '+ session['last_name'],username = session['username'],msgs=msg,name=session['first_name'])
        else:
            return redirect(url_for('not_found'))
    # User is not loggedin redirect to login page
    return redirect(url_for('smart_farming_login'))



@app.route('/admin_log', methods=['GET', 'POST'])
def admin_log():
    if 'loggedin' in session:
        if session['username'] == "FTC-admin":
            msg=''
            txt=''
            final = ()
            final_date =()
            final_res =()
            count_date=0
            count = 0
            if request.method == 'POST' and 'username' in request.form :
                username = request.form['username']
                mycursor = mysql.connection.cursor()
                mycursor.execute("SELECT id FROM accounts WHERE username =  %s",(username,))
                res = mycursor.fetchall()
                if res:
                    mycursor.execute("SELECT serial_number FROM user_device WHERE id = %s",(res,))
                    res = mycursor.fetchall()
                    if res:
                        res = numpy.array(res)
                        count_device = res.size
                        final = ()
                        count = 0
                        # get data from database in dict
                        mycursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
                        for i in range(count_device):
                            mycursor.execute("SELECT * FROM `device_log` WHERE serial_number = %s ORDER BY `device_log`.`date` DESC ,`device_log`.`time` DESC",(res[count]))
                            natij = mycursor.fetchall()
                            final = final + natij
                            count = count + 1
                        count = 0
                        for i in range(count_device):
                            mycursor.execute("SELECT * FROM `device_log` WHERE serial_number = %s ORDER BY `device_log`.`date` DESC ,`device_log`.`time` DESC",(res[count]))
                            date = mycursor.fetchall()
                            dates = re.findall(r"\d+, \d+, \d+", str(date))
                            for date2 in dates:
                                year = date2[0:4]
                                month = date2[5:7]
                                day = date2[9:11]
                                shamsi ={'jdate': jdatetime.date.fromgregorian(day=int(day),month=int(month),year=int(year))}
                                shamsi =(shamsi,)
                                final_date = final_date + shamsi
                                count_date = count_date+1
                            count = count + 1
                        count =0
                        for i in range(count_date):
                            n = final[count]
                            m = final_date[count]
                            n.update(m)
                            n = (n,)
                            final_res = final_res + n
                            count = count+1
                        txt = "کشاورز مورد نظر یافت شد."
                        mycursor.close()
                    else:
                        txt = "برای کشاورز" +' '+ username +' '+ "هیچ دستگاهی برای نمایش وجود ندارد"
                        mycursor.close()
                else:
                    txt = "کشاورز " +' '+ username +' '+ " وجود ندارد."
                mycursor.close()
                msg="نتیجه جستجو برای کشاورز : " + username
            return render_template('admin_log.html',logs = final_res,msg = msg,txt = txt,name=session['first_name'])
        else:
            return redirect(url_for('not_found'))
    # User is not loggedin redirect to login page
    return redirect(url_for('smart_farming_login'))





@app.route('/log')
def log():
    if 'loggedin' in session:
        msg=''
        mycursor = mysql.connection.cursor()
        mycursor.execute("SELECT serial_number FROM user_device WHERE id_user = %s",(session['id'],))
        res = mycursor.fetchall()
        if res:
            res = numpy.array(res)
            count_device = res.size
            final = ()
            final_date =()
            final_res =()
            count_date=0
            count = 0
            # get data from database in dict
            mycursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            for i in range(count_device):
                mycursor.execute("SELECT * FROM `device_log` WHERE serial_number = %s ORDER BY `device_log`.`date` DESC ,`device_log`.`time` DESC",(res[count]))
                natij = mycursor.fetchall()
                final = final + natij
                count = count + 1
            count = 0
            for i in range(count_device):
                mycursor.execute("SELECT * FROM `device_log` WHERE serial_number = %s ORDER BY `device_log`.`date` DESC ,`device_log`.`time` DESC",(res[count]))
                date = mycursor.fetchall()
                dates = re.findall(r"\d+, \d+, \d+", str(date))
                for date2 in dates:
                    year,month,day = date2.split(',')
                    shamsi ={'jdate': jdatetime.date.fromgregorian(day=int(day),month=int(month),year=int(year))}
                    shamsi =(shamsi,)
                    final_date = final_date + shamsi
                    count_date = count_date+1
                count = count + 1
            count =0
            for i in range(count_date):
                n = final[count]
                m = final_date[count]
                n.update(m)
                n = (n,)
                final_res = final_res + n
                count = count+1
            mycursor.close()
        else:
            final_res = ''
            mycursor.close()
            msg = session['first_name'] +' '+ session['last_name'] +' '+ "هیچ اطلاعاتی برای نمایش این دستگاه وجود ندارد"
        
        return render_template('log.html', logs = final_res, msg = msg,name=session['first_name'])
    # User is not loggedin redirect to login page
    return redirect(url_for('smart_farming_login'))
    

@app.route('/admin_add_device',methods=['GET', 'POST'])
def admin_add_device():
    # Check if user is loggedin
    if 'loggedin' in session:
        if session['username'] == "FTC-admin":
            msg =''
            if request.method == 'POST' and 'model_name' in request.form and 'serial_number' in request.form and 'password_device' in request.form and 'output' in request.form and 'input' in request.form and 'device_image' in request.files:
                # Create variables for easy access
                model_name = request.form['model_name']
                serial_number = request.form['serial_number']
                password_device = request.form['password_device']
                output = request.form['output']
                input = request.form['input']
                device_image = request.files['device_image']
                cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
                cursor.execute('SELECT * FROM device WHERE serial_number = %s ', (serial_number,))
                device = cursor.fetchone()
                cursor.execute('SELECT * FROM device WHERE password_device = %s', (password_device,))
                device1 = cursor.fetchone()
                if not device and not device1:
                        device_image2 = re.search(r"'\w+.+' ", str(device_image))
                        device_image2 = device_image2.group()
                        device_image2 = re.search(r"\w+.+'", str(device_image2))
                        device_image2 = device_image2.group()
                        device_image2 = re.sub(r"'", '', str(device_image2))
                        cursor.execute('INSERT INTO  device ( model_name , serial_number, password_device, output, input, device_image) VALUES (%s,%s,%s,%s,%s,%s)', (model_name, serial_number, password_device, output, input, device_image2))
                        cursor.connection.commit()
                        date1 = date.today()
                        date1 = str(date1)
                        cursor.execute('UPDATE device SET create_date = %s WHERE device.serial_number = %s',(date1,serial_number))
                        time1 = time.localtime()
                        time1 = time.strftime("%H:%M:%S", time1)
                        cursor.execute('UPDATE device SET create_time = %s WHERE device.serial_number = %s',(time1,serial_number))
                        cursor.connection.commit()
                        cursor.close()
                        device_image_name = secure_filename(device_image.filename)
                        device_image.save(os.path.join(app.config['UPLOAD_FOLDER'], device_image_name))
                        msg ='دستگاه با موفقیت به لیست اضافه شد'
                        cursor.close()
                        return render_template('admin_add_device.html', msg=msg)
                elif device:
                    msg ='دستگاهی با این سریال از قبل وجود دارد!'
                    cursor.close()
                    return render_template('admin_add_device.html', msg=msg)
                elif device1:
                    msg ='دستگاهی با این رمز از قبل وجود دارد!'
                    cursor.close()
                    return render_template('admin_add_device.html', msg=msg)
                else :
                    cursor.close()
                    msg ='دستگاه از قبل وجود دارد!'
                    return render_template('admin_add_device.html', msg=msg)
            return render_template('admin_add_device.html', username=session['username'],name=session['first_name'])
        else:
            return redirect(url_for('not_found'))
    # User is not loggedin redirect to login page
    return redirect(url_for('smart_farming_login'))



# This is 404 - not found page 
@app.route('/not_found')
def not_found():
        return render_template('not_found.html')


@app.route('/toggled_pin/<current_status>/<serial_dev>/<pin_num>',methods=['GET', 'POST']) 
def toggled_pin(current_status,serial_dev,pin_num):
    try:
        if current_status == 'on':
            current_status = 'off'
            pin(serial_dev,current_status,pin_num) 
            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            cursor.execute('SELECT user_model_name FROM device WHERE serial_number = %s', (serial_dev,))
            model = cursor.fetchone()
            cursor.execute('INSERT INTO device_log (serial_number, subject, time, date, user_model_name) VALUES (%s, %s, %s, %s, %s)',
                           (serial_dev, 'Pin ' + pin_num + ' ' + current_status, datetime.datetime.now().strftime("%H:%M:%S"), datetime.datetime.now().strftime("%Y-%m-%d"), model['user_model_name'],))  
            cursor.connection.commit()          
            cursor.execute('SELECT pin_stat FROM user_device WHERE serial_number = %s AND id_user = %s', (serial_dev, session['id']))
            stat = cursor.fetchone()
            stats = list(filter(None, stat['pin_stat'].split('&')))
            stats[int(pin_num)-1] = current_status
            newStats = '&'.join(stats)
            cursor.execute('UPDATE user_device SET pin_stat = %s WHERE serial_number = %s',(newStats,serial_dev))
            cursor.connection.commit()
            cursor.close()
            return current_status               
        else:
            current_status = 'on'
            pin(serial_dev,current_status,pin_num)
            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            cursor.execute('SELECT user_model_name FROM device WHERE serial_number = %s', (serial_dev,))
            model = cursor.fetchone()
            # print(model)
            cursor.execute('INSERT INTO device_log (serial_number, subject, time, date, user_model_name) VALUES (%s, %s, %s, %s, %s)',
                           (serial_dev, 'Pin ' + pin_num + ' ' + current_status, datetime.datetime.now().strftime("%H:%M:%S"), datetime.datetime.now().strftime("%Y-%m-%d"), model['user_model_name'],)) 
            print(20) 
            cursor.connection.commit()   
            cursor.execute('SELECT pin_stat FROM user_device WHERE serial_number = %s AND id_user = %s', (serial_dev, session['id']))
            stat = cursor.fetchone()
            stats = list(filter(None, stat['pin_stat'].split('&')))
            stats[int(pin_num)-1] = current_status
            newStats = '&'.join(stats)
            cursor.execute('UPDATE user_device SET pin_stat = %s WHERE serial_number = %s',(newStats,serial_dev))
            cursor.connection.commit()
            cursor.close()
            return current_status
    except Exception as e:
        print(f"An exception occurred: {e}")
        print("device is not connected")
        return "device is not connected"
    
# check device is alive or not
@app.route('/get_status')
def get_status():
    ser = request.args.get('ser')
    mycursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    mycursor.execute("SELECT `con_num` FROM `user_device` WHERE `serial_number` = %s",(ser,))
    status = mycursor.fetchall()
    mycursor.close()
    status = re.search(r"\d", str(status))
    try:
        status = status.group()
        if status == '0':
            sta = 'آفلاین'
        else:
            sta = 'آنلاین'
    except:
        sta = 'آفلاین'
    return sta

def generate_csv_from_http(url,day1,day2):
    try:
        response = requests.get(url)
        response.raise_for_status() 
        data = response.text
        rows = data.split('&')
        parsed_rows = []
        for index, row in enumerate(rows):
            columns = row.split(',')
            date_str = columns[-2]
            if '/' in date_str:
                date = datetime.datetime.strptime(date_str, '%d/%m/%Y')
            elif '-' in date_str:
                date = datetime.datetime.strptime(date_str, '%Y-%m-%d')
            else:
                date = datetime.datetime.strptime(date_str, '%Y.%m.%d')
            if(index < 5):
                print(columns)
            parsed_rows.append((*columns[:-2], date, columns[-1]))
            if index == len(rows) - 2:
                break

        sorted_rows = sorted(parsed_rows, key=lambda x: x[-2])

        # Convert string dates to datetime objects
        start_date = datetime.datetime.strptime(day1, '%Y-%m-%d')
        end_date = datetime.datetime.strptime(day2, '%Y-%m-%d')

        filtered_rows = [row for row in sorted_rows if start_date <= row[-2] <= end_date]

        final_rows = []
        for row in filtered_rows:
            formatted_row = ','.join([str(item) if not isinstance(item, datetime.datetime) else item.strftime('%Y-%m-%d') for item in row])
            final_rows.append(formatted_row)

        with open("data.csv", "w", newline="") as csvfile:
            csv_writer = csv.writer(csvfile)
            for row in final_rows:
                csv_writer.writerow(row.split(','))

        return True
    except Exception as e:
        print("Error:", str(e))
        return False

@app.route('/getCSV', methods=['GET', 'POST'])
def getCSV():
    day1 = request.form.get('Day1')
    day2 = request.form.get('Day2')
    dev_ser = request.form.get('dev_ser')
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('SELECT * FROM user_device WHERE serial_number = %s AND id_user = %s', (dev_ser, session['id']))
    device = cursor.fetchone()
    if device:
        cursor1 = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor1.execute('SELECT * FROM device WHERE serial_number = %s', (dev_ser,))
        device1 = cursor1.fetchone()           
        http_url = 'http://185.255.90.31:10000/getExcel'+str(device1['id'])
    if generate_csv_from_http(http_url,day1,day2):
        with open("data.csv", "rb") as f:
            csv_data = f.read()
        os.remove("data.csv")
        response = make_response(csv_data)
        response.headers.set("Content-Type", "text/csv")

        response.headers.set("Content-Disposition", "attachment", filename="data.csv")

        return response
    else:
        return "Error generating CSV file from HTTP data."

@app.route('/sensor_show',methods=['GET', 'POST'])
def sensor_show():
    # Check if user is loggedin
    if 'loggedin' in session:
        if request.method == 'POST':
            dev_ser = request.form['dev_ser']
            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            cursor.execute('SELECT * FROM user_device WHERE serial_number = %s AND id_user = %s', (dev_ser, session['id']))
            device = cursor.fetchone()
            if device:
                cursor1 = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
                cursor1.execute('SELECT * FROM device WHERE serial_number = %s', (dev_ser,))
                device1 = cursor1.fetchone()
                url = 'http://185.255.90.31:10000/receive_dev' + str(device1['id'])
            data = fetch_data_from_http(url)
            if device['sensor_titles'] and device['sensor_titles'][0] is not None:
                names = list(filter(None, device['sensor_titles'].split('&')))
            else:
                names = []
            if device1['device_type'] == "eshtad" :
                return render_template('sensor_data_eshtad.html', serial_number=dev_ser, data2=data,sensorNames = names,sensorNum = device['sensor_number'])
            else :
                return render_template('sensor_data.html', serial_number=dev_ser, data2=data,sensorNames = names,sensorNum = device['sensor_number'])
    # User is not loggedin redirect to login page
    return redirect(url_for('smart_farming_login'))

@app.route('/sensor_data',methods = ['GET','POST'])
def sensor_data():
    if 'loggedin' in session:
        if request.method == 'POST':
            dev_ser = request.form['dev_ser']
            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            cursor.execute('SELECT * FROM user_device WHERE serial_number = %s AND id_user = %s', (dev_ser, session['id']))
            device = cursor.fetchone()
            if device:
                cursor1 = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
                cursor1.execute('SELECT * FROM device WHERE serial_number = %s', (dev_ser,))
                device1 = cursor1.fetchone()    
                url = 'http://185.255.90.31:10000/receive_dev' + str(device1['id'])
            print("url : ",url)
            data2 = fetch_data_from_http(url)
            return data2
    # User is not loggedin redirect to login page
    return redirect(url_for('smart_farming_login'))

@app.route('/forgot_password',methods=['GET', 'POST'])
def forgot_password():
    return render_template('forgot_password.html')

@app.route('/forgot_password_mail', methods=['GET', 'POST'])
def forgot_password_mail():
    msg = ''
    if request.method == 'POST' and 'email' in request.form and 'username' in request.form:
        email = request.form['email']
        username = request.form['username']
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE mail = %s AND username = %s', (email,username,))
        account = cursor.fetchone()

        if account:
            reset_token = str(uuid.uuid4())
            # Store reset_token and expiration time in the database
            cursor.execute('UPDATE accounts SET reset_token = %s, token_expiration = %s WHERE id = %s', (reset_token, datetime.datetime.utcnow() + datetime.timedelta(minutes=30), account['id']))
            mysql.connection.commit()

            reset_url = url_for('reset_password', token=reset_token, _external=True)
            send_email(email, "بازیابی رمز عبور" ,f'برای بازیابی رمز عبور خود بر روی لینک زیر کلیک کنید : \n{reset_url}')

            flash('Password reset email sent. Check your inbox.', 'success')
            return redirect(url_for('smart_farming_login'))
        else:
            msg = 'ایمیل یا نام کاربری وارد شده نادرست است.'

    return render_template('forgot_password_mail.html', msg=msg)


@app.route('/forgot_password_phone', methods=['GET', 'POST'])
def forgot_password_phone():
    msg = ''
    if request.method == 'POST' and 'phone' in request.form and 'username' in request.form:
        phoneNum = request.form['phone']
        username = request.form['username']
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE phone_number = %s AND username = %s', (phoneNum,username,))
        account = cursor.fetchone()

        if account:
            url = 'http://185.255.90.31:10000/recover_password'
            response = requests.post(url,user = username , phone = phoneNum)
            if response.status_code == 200:
                        print('success')
            return redirect(url_for('smart_farming_login'))
        else:
            msg = 'شماره تماس یا نام کاربری وارد شده نادرست است.'

    return render_template('forgot_password_phone.html', msg=msg)

def send_email(receiver_email, subject, text):

    # SMTP Configuration
    port = 465  # For SSL
    smtp_server = "mail.fanavaran-sharif.ir"
    sender_email = "CRM@fanavaran-sharif.ir"  # Enter your address
    password = '5+5]FnNX0bR1'   # Enter your app password

    # Message Configuration
    message = MIMEMultipart()
    message["Subject"] = subject
    message["From"] = sender_email
    message["To"] = receiver_email
    part = MIMEText(text, "plain", "utf-8")
    message.attach(part)

    context = ssl.create_default_context()

    with smtplib.SMTP_SSL(smtp_server, port, context=context) as server:
        server.login(sender_email, password)
        server.sendmail(sender_email, receiver_email, message.as_string())


@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    msg = ''
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('SELECT * FROM accounts WHERE reset_token = %s AND token_expiration > %s', (token, datetime.datetime.utcnow()))
    account = cursor.fetchone()

    if account:
        if request.method == 'POST' and 'new_password' in request.form:
            new_password = request.form['new_password']
            # Update the password and reset_token in the database
            cursor.execute('UPDATE accounts SET password = MD5(%s), reset_token = NULL, token_expiration = NULL WHERE id = %s', (new_password, account['id']))
            mysql.connection.commit()

            flash('Password reset successful. You can now log in with your new password.', 'success')
            return redirect(url_for('smart_farming_login'))
        else:
            msg = "رمز جدید خود را وارد نکردید."
            return render_template('reset_password.html', msg=msg)
    else:
        flash('Invalid or expired token.', 'danger')
        return redirect(url_for('smart_farming_login'))

@app.route('/remove_device/<serial_number>', methods=['GET','POST'])
def remove_device(serial_number):
    # Check if user is logged in
    if 'loggedin' in session:
        msg = ''
        # Check if the device exists and belongs to the user
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM user_device WHERE serial_number = %s AND id_user = %s', (serial_number, session['id']))
        device = cursor.fetchone()
        
        if device:
            # Delete the device from user_device table
            cursor.execute('DELETE FROM user_device WHERE serial_number = %s AND id_user = %s', (serial_number, session['id']))
            mysql.connection.commit()
            cursor.close()
            msg = 'دستگاه با موفقیت حذف شد'
        else:
            cursor.close()
            msg = 'شما مجاز به حذف این دستگاه نیستید'
        
        # Redirect back to the page where the removal was initiated
        return redirect(url_for('manage_device'))
    
    return redirect(url_for('smart_farming_login'))

def chartData(url,day1,day2):
    try:
        n=20
        response = requests.get(url)
        response.raise_for_status() 
        data = response.text
        rows = data.split('&')
        parsed_rows = []
        date_indices = [-2, -1]  # Indices of the last two columns (date and time)
        for index, row in enumerate(rows):
            columns = row.split(',')
            # date_str = columns[4]
            date_str = columns[date_indices[0]]
            time_str = columns[date_indices[1]]
            if '/' in date_str:
                date = datetime.datetime.strptime(date_str, '%d/%m/%Y')
            elif '-' in date_str:
                date = datetime.datetime.strptime(date_str, '%Y-%m-%d')
            else:
                date = datetime.datetime.strptime(date_str, '%Y.%m.%d')
            columns = columns[:date_indices[0]]
            parsed_rows.append((columns, date))
            # parsed_rows.append((columns[0], columns[1], columns[2], columns[3], date, columns[5]))
            if index == len(rows) - 2:
                break
        # sorted_rows = sorted(parsed_rows, key=lambda x: x[4])
        # sort based on date
        sorted_rows = sorted(parsed_rows, key=lambda x: x[1])
        # Convert string dates to datetime objects
        start_date = datetime.datetime.strptime(day1, '%Y-%m-%d')
        end_date = datetime.datetime.strptime(day2, '%Y-%m-%d')
        
        final_rows = []
        counter = {}  # Dictionary to keep track of data points per row
        
        for row,date in sorted_rows:
            # if row not in counter:
            #     counter[row] = 0
            row_tuple = tuple(row)  # Convert the list to a tuple
            if row_tuple not in counter:
                counter[row_tuple] = 0
            if start_date <= date and date <= end_date and counter[row_tuple] < n:
                formatted_row = ','.join(row + [date.strftime('%Y-%m-%d')])
                final_rows.append(formatted_row)
                counter[row_tuple] += 1
        
        finalstr = '&'.join(final_rows)
        
        return finalstr
                    
    except Exception as e:
        print("Error:", str(e))
        return ""

@app.route('/sensor_showChart',methods=['GET', 'POST'])
def sensor_showChart():
    # Check if user is loggedin
    if 'loggedin' in session:
        if request.method == 'POST' :
            day1 = request.form['date1']
            day2 = request.form['date2']
            dev_ser = request.form['dev_ser']
            year1, month1, date1 = map(int, day1.split('/'))
            year2, month2, date2 = map(int, day2.split('/'))
            gregorian_date1 = JalaliDate(year1,month1,date1).to_gregorian()
            gregorian_date2 = JalaliDate(year2,month2,date2).to_gregorian()
            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            cursor.execute('SELECT * FROM user_device WHERE serial_number = %s AND id_user = %s', (dev_ser, session['id']))
            device = cursor.fetchone()
            if device:
                cursor1 = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
                cursor1.execute('SELECT * FROM device WHERE serial_number = %s', (dev_ser,))
                device1 = cursor1.fetchone()               
                http_url = 'http://185.255.90.31:10000/getExcel'+str(device1['id'])
            res = chartData(http_url,gregorian_date1.isoformat(),gregorian_date2.isoformat())
            if device['sensor_titles'] and device['sensor_titles'][0] is not None:
                names = list(filter(None, device['sensor_titles'].split('&')))
            else:
                names = []
            return render_template('sensor_show.html',serial_number = dev_ser,result = res,sensorNum = device['sensor_number'],sensorNames = names)
    # User is not loggedin redirect to login page
    return redirect(url_for('smart_farming_login'))


@app.route('/save_senario', methods = ['GET','POST'])
def save_senario():
    if 'loggedin' in session:
        if request.method == 'POST':
            formData = request.form['form_data']
            dev_ser = request.form['dev_ser']
            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            cursor.execute('SELECT * FROM user_device WHERE serial_number = %s AND id_user = %s', (dev_ser, session['id']))
            device = cursor.fetchone()
            if device :
                cursor.execute('UPDATE user_device SET senario = %s WHERE serial_number = %s', (formData, dev_ser))
                mysql.connection.commit()
                cursor.close()
                return "saved"
    return render_template(url_for('smart_farming_login'))

@app.route('/get_senario', methods = ['GET','POST'])
def get_senario():
    if 'loggedin' in session:
        if request.method == 'POST':
            dev_ser = request.form['dev_ser']
            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            cursor.execute('SELECT * FROM user_device WHERE serial_number = %s AND id_user = %s', (dev_ser, session['id']))
            device = cursor.fetchone()
            return device['senario']
    return render_template(url_for('smart_farming_login'))   
        
        
def setSenario(dev_ser,stat,senarioId,sessionId,url) : 
    with app.app_context(): 
        del timeOuts[sessionId][dev_ser][senarioId]
        return requests.get(url)

timeOuts  = defaultdict(lambda: defaultdict(dict))

def startTimeout(timeNeeded, dev_ser,stat,senarioId,sessionId,url,completion_event):
    with app.app_context():
        timeOuts[sessionId][dev_ser][senarioId] = threading.Timer(timeNeeded, setSenario, args=(dev_ser,stat,senarioId,sessionId,url))
        timeOuts[sessionId][dev_ser][senarioId].start()
        timeOuts[sessionId][dev_ser][senarioId].join()
        completion_event.set()  

@app.route('/start_timeout', methods = ['GET','POST'])
def strat_timeout() :
    timeNeeded = float(request.form['timeNeeded'])
    dev_ser = request.form['dev_ser']
    pinVal = request.form['pinVal']
    statusPin = request.form['statusPin']
    senarioId = request.form['senarioId']
    sessionId = session['id']
    match = re.match(r'pin(\d+)', pinVal)
    pinNum = match.group(1)
    url = request.url_root + url_for('toggled_pin',current_status = statusPin,serial_dev = dev_ser,pin_num = pinNum)
    completion_event = threading.Event()
    startTimeout(timeNeeded, dev_ser,statusPin,senarioId,sessionId,url,completion_event)
    completion_event.wait()
    return "started"

@app.route('/cancel_timeout', methods=['POST'])
def cancel_timeout():
    # Cancel the timeout for the specified client
    dev_ser = request.form['dev_ser']
    senarioId = request.form['senarioId']
    timeOuts[session['id']][dev_ser][senarioId].cancel()
    del timeOuts[session['id']][dev_ser][senarioId]
    return "canceled"

@app.route('/save_logos' , methods = ["POST"])
def save_logos():
    if 'loggedin' in session:
        pin_logos = request.form['logos']
        dev_ser = request.form['dev_ser']
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM user_device WHERE serial_number = %s AND id_user = %s', (dev_ser, session['id']))
        device = cursor.fetchone()
        if device :
            cursor.execute('UPDATE user_device SET pin_logo = %s WHERE serial_number = %s', (pin_logos, dev_ser))
            mysql.connection.commit()
            cursor.close()
            return "saved"
    return render_template(url_for('smart_farming_login'))

@app.route('/save_pinNum' , methods = ["POST"])
def save_pinNum():
    if 'loggedin' in session:
        pinNum = request.form['pinNum']
        dev_ser = request.form['dev_ser']
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM user_device WHERE serial_number = %s AND id_user = %s', (dev_ser, session['id']))
        device = cursor.fetchone()
        if device :
            cursor.execute('UPDATE user_device SET pinNumber = %s WHERE serial_number = %s', (pinNum, dev_ser))
            mysql.connection.commit()
            cursor.execute('UPDATE device SET output = %s WHERE serial_number = %s', (pinNum, dev_ser))
            mysql.connection.commit()
            cursor.close()
            getDevDatas()
            return "saved"
    return render_template(url_for('smart_farming_login'))
        
        
@app.route('/save_status',methods=['POST'])
def save_status():
    if 'loggedin' in session:
        stats = request.form['stats']
        dev_ser = request.form['dev_ser']
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM user_device WHERE serial_number = %s AND id_user = %s', (dev_ser, session['id']))
        device = cursor.fetchone()
        if device :
            cursor.execute('UPDATE user_device SET pin_stat = %s WHERE serial_number = %s', (stats, dev_ser))
            mysql.connection.commit()
            cursor.close()
            return "saved"
    return render_template(url_for('smart_farming_login'))

@app.route('/save_newSensors' , methods = ["POST"])
def save_newSensors():
    if 'loggedin' in session:
        sensorNum = request.form['sensorNum']
        dev_ser = request.form['dev_ser']
        sensorTitles = request.form['sensorTitles']
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM user_device WHERE serial_number = %s AND id_user = %s', (dev_ser, session['id']))
        device = cursor.fetchone()
        if device :
            cursor.execute('UPDATE user_device SET sensor_number = %s, sensor_titles = %s WHERE serial_number = %s', (sensorNum,sensorTitles, dev_ser))
            mysql.connection.commit()
            cursor.execute('UPDATE device SET input = %s WHERE serial_number = %s', (sensorNum , dev_ser))
            mysql.connection.commit()
            cursor.close()
            getDevDatas()
            return "saved"
    return render_template(url_for('smart_farming_login'))
# 5x^2 + 3x + 5 = a
# def encodeData(data):
#     x = sp.symbols('x')
#     components = data.split('&')
#     modified_components = []
#     for component in components:
#         modified_data = component.split('.')
#         for dt in modified_data:
#             equation = 5*x**2 + 3*x + 5 - int(dt)
#             solutions = sp.solve(equation, x)
#             positive_root = max(solutions, key=lambda x: x > 0)
#             modified_components.append(positive_root)

#     finalRes = '&'.join(['.'.join(modified_data) for modified_data in modified_components])
#     return finalRes
        
        

#run server
if __name__ == "__main__":
    
    # Run second server for devices
    # t1=Thread(target=server)
    
    # Start in Thread
    # t1.start()

    # Run Web service on server ip and 10000 port
    app.run(host='0.0.0.0', port = 8000) 