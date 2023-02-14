#PROJECT : E-AUTHENTICATION SYSTEM USING OTP AND QRCODE

from flask import Flask, render_template, request, redirect, url_for, session
from flask_mysqldb import MySQL
from flask import *  
from flask_mail import *  
from itsdangerous import URLSafeTimedSerializer,SignatureExpired

#from werkzeug.security import generate_password_hash,check_password_hash
from random import *  
import MySQLdb.cursors
import re
import qrcode
import cv2
import time
import bcrypt


location = '/home/bhavyasri/qrcodes'

app = Flask(__name__)
mail = Mail(app)
  
app.config["MAIL_SERVER"]='smtp.gmail.com'  
app.config["MAIL_PORT"] = 465      
app.config["MAIL_USERNAME"] = '*******@gmail.com'  
app.config['MAIL_PASSWORD'] = '*********'  
app.config['MAIL_USE_TLS'] = False  
app.config['MAIL_USE_SSL'] = True  
#app.config['MAIL_SENDER'] = 'walkersunion345679@gmail.com'
app.config['SECURITY_PASSWORD_SALT'] = 'my_precious_two'

mail = Mail(app)  

s = URLSafeTimedSerializer('Thisisasecret!')


otp = randint(000000,999999) 

app.secret_key = 'your secret key'

app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = '********'
app.config['MYSQL_DB'] = 'authentication'

mysql = MySQL(app)

@app.route('/')
@app.route('/login', methods =['GET', 'POST'])
def login():
    msg1=''
    error=None
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
        username = request.form['username']
        username = username.strip()
        password = request.form['password']
        password = password.rstrip()
        #salt = bcrypt.gensalt()
        #hashed = bcrypt.hashpw(password, salt)
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE username = % s', (username, ))
        account = cursor.fetchone()
        if account:
            session['id'] = account['id']
            session['loggedin'] = True
            session['username'] = account['username']
            session['email'] = account['email']
            email1 = account['email']
            hashed = account['password']
            print('database has hashed: {} {}'.format(hashed,type(hashed)))
            print('form supplied passwd: {} {}'.format(password,type(password)))
            hashed2 = bcrypt.hashpw(password.encode('utf-8'),hashed.encode('utf-8'))
            hashed2_str = hashed2.decode('utf-8')
            print('rehash is: {} {}'.format(hashed2_str,type(hashed2_str)))
            if hashed2_str == hashed:
            	session['id'] = account['id']
            	session['loggedin'] = True
            	msg1 = 'Select type of Login options !'
            	flash(msg1)
            	if request.form["LoginBtn1"]=="Login With OTP":
            		msg = Message('OTP',sender = 'bhavyasri5e5@gmail.com',recipients = [email1])
            		msg.body = str(otp)
            		mail.send(msg)
            		return render_template('verify.html')
            		#return render_template('Homepage.html')
            		
            	elif request.form["LoginBtn1"]=="Login With QR" :
            		qr = qrcode.QRCode(version=1,error_correction=qrcode.constants.ERROR_CORRECT_H,box_size=5,border=5)
            		qr.add_data(username + ' ' + password+' '+str(otp))
            		qr.make(fit=True)
            		img = qr.make_image(fill_color='black', back_color='white')
            		img.save(location+'qrcode_'+str(username) +'.png')
            		print('QR Code generated!!')
            		subject = "Login with QR"
            		message = "Hi,"+ str(username)+", the QR for logging into our system is attached. Please login within 5 minutes."
            		msg = Message(subject,sender='bhavyasri5e5@gmail.com',recipients=[email1])
            		msg.body = message
            		with app.open_resource(location+'qrcode_'+str(username) +'.png') as fp:
            			msg.attach(location+'qrcode_'+str(username)+'.png',(str(username)+"/png"),fp.read())
            			mail.send(msg)
            		cam = cv2.VideoCapture(-1)
            		detector = cv2.QRCodeDetector()
            		timeout = time.time() + 60*5
            		while True:
            			_, img = cam.read()
            			data, bbox, _ = detector.detectAndDecode(img)
            			if (cv2.waitKey(1) & 0xFF) == ord('q'):
            				print('here')
            				break
            			if data:
            				print("QR Code detected-->", data)
            				d = data.split()
            				if (d[0]==username and d[1]==password and d[2]==str(otp)):
            					cam.release()
            					cv2.destroyAllWindows()
            					#return render_template('index.html',msg='Login successful...!')
            					return redirect(url_for('home'))
            				else:
            					cam.release()
            					cv2.destroyAllWindows()
            					return render_template('login.html',msg='Login unsuccessful...try again...!')
            			elif time.time() > timeout:
            				cam.release()
            				cv2.destroyAllWindows()
            				return render_template('login.html',msg='sorry! Time limit exceeded....try again...!')
            			cv2.imshow("place your QR Code near cam properly..!\npress Esc if you want to exit..!", img)
            			if cv2.waitKey(1) & 0xFF == ord('q'):
            				break
            		cam.release()
            		cv2.destroyAllWindows()
            	else:
            		return render_template('login.html',msg = msg1)
            else:
            	return render_template('login.html',msg='Incorrect password')
        elif request.form["LoginBtn1"]=="Forgot Password":
        	return render_template('recieve.html')
        else:
        	msg1 = 'Incorrect username !'
        	return render_template('login.html', msg = msg1)
        
    else:
    	msg1='enter username and password'
    	return render_template('login.html', msg = msg1)
    
 	 
@app.route('/validate',methods=["POST"])   
def validate():
	user_otp = request.form['otp']
	if otp == int(user_otp):
		session['loggedin'] = True 
		msg="Email  verification is  successful"  
		#return render_template('index.html',msg=msg)
		return redirect(url_for('home'))
	else:
		msg = "failure, OTP does not match"
		return render_template('login.html',msg=msg)   
		

@app.route('/logout')
def logout():
	try :
		session.pop('loggedin', None)
		session.pop('id', None)
		session.pop('username', None)
		return redirect(url_for('login'))
	except Exception as err:
		flash('some kind of error '+str(err))
		return redirect( url_for('login') )

@app.route('/register', methods =['GET', 'POST'])
def register():
    msg = ''
    if request.method == 'POST' and 'username' in request.form and 'first_name' in request.form and 'last_name' in request.form and 'phone_number' in request.form and 'email' in request.form and 'password' in request.form :
        username = request.form['username']
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        phone_number = request.form['phone_number']
        password = request.form['password']
        hashed = bcrypt.hashpw(password.encode('utf-8'),bcrypt.gensalt())
        hashed_str = hashed.decode('utf-8')
        print(password, type(password), hashed, hashed_str)
        email = request.form['email']
        confirmed = False
        
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE username = % s', (username, ))
        account = cursor.fetchone()
        if account:
            msg = 'Account already exists !'
        elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            msg = 'Invalid email address !'
        elif not re.match(r'[A-Za-z0-9]+', username):
            msg = 'Username must contain only characters and numbers !'
        elif not re.match(r'[A-Za-z]+', first_name):
            msg = 'First name must contain only characters...!'
        elif not re.match(r'[A-Za-z]+', last_name):
            msg = 'Last name must contain only characters...!'
        elif not re.match(r'[0-9]+', phone_number):
            msg = 'Phone number must contain only digits.....!'
        elif not username or not password or not email or not first_name or not last_name:
            msg = 'Please fill out the form !'
        else:
        	cursor.execute('INSERT INTO accounts VALUES (NULL, % s, % s, % s, %s, %s, %s)', (username,first_name,last_name,phone_number, email,hashed_str,))
        	mysql.connection.commit()
        	msg = 'registered successfully.. !'
    elif request.method == 'POST':
        msg = 'Please fill out the form !'
    return render_template('register.html', msg = msg)
 
@app.route('/passwordreset', methods=['GET', 'POST'])
def passwordreset():
	username = request.form['username']
	cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
	cursor.execute('SELECT * FROM accounts WHERE username = % s', (username, ))
	account = cursor.fetchone()
	if account:
		session['id'] = account['id']
		session['username'] = account['username']
		email = account['email']
		token = s.dumps(email, salt='email-confirm')
		msg = Message('Confirm Email', sender='bhavyasri5e5@gmail.com', recipients=[email])
		link = url_for('confirm_email', token=token, _external=True)
		msg.body = 'Your link is {}'.format(link)
		mail.send(msg)
		return '<h1>Check your mail for changing your password!</h1>'
	else :
		return render_template('login.html',msg='Sorry...!,please give correct username')
    #return render_template('reset.html')
    
     

@app.route('/confirm_email/<token>')
def confirm_email(token):	
	try:
		email = s.loads(token, salt='email-confirm', max_age=3600)
	except SignatureExpired:
		return '<h1>The token is expired!</h1>'
		
	#confirmed = True
	#return '<h1>The token works!</h1>'
	return render_template('reset.html')
	
@app.route('/reset',methods=['Get','Post'])
def reset():
	if request.method == 'POST' and 'username' in request.form and 'password' in request.form and 'confirmPassword' in request.form:
        	username = request.form['username']
        	password = request.form['password']
        	confirmPassword = request.form['confirmPassword']
        	if (password!=confirmPassword):
        		return render_template('reset.html',msg="both password fields must be entered same")
        	else:
        		hashed = bcrypt.hashpw(password.encode('utf-8'),bcrypt.gensalt())
        		hashed_str = hashed.decode('utf-8')
        		print(password, type(password), hashed, hashed_str)
        		cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        		cursor.execute('SELECT * FROM accounts WHERE username = % s', (username, ))
        		account = cursor.fetchone()
        		if account:
        			session['id'] = account['id']
        			session['username'] = account['username']
        			cursor.execute('UPDATE accounts SET password = %s where username= %s ',(hashed_str,session['username'], ))
        			mysql.connection.commit()
        			return render_template('login.html',msg='password successfully changed')
        		else :
        			msg='Account with given username is not present\n,If you didnot register before,Please register..!'
        			return render_template('login.html',msg=msg)
        		   		
	
@app.route('/home',methods=['GET', 'POST'])
def home():
    # Check if user is loggedin
    if 'loggedin' in session:
    	return render_template('home.html',username=session['username'])
    return redirect(url_for('login'))

    	
	
		
@app.route('/profile',methods=['GET', 'POST'])
def profile():
    if 'loggedin' in session:
        # We need all the account info for the user so we can display it on the profile page
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE id = %s', (session['id'],))
        account = cursor.fetchone()
        # Show the profile page with account info
        return render_template('profile.html', account=account)
    # User is not loggedin redirect to login page
    return redirect(url_for('login'))
    
@app.route('/delete',methods=['GET','POST'])
def delete():
	#session['loggedin'] = True
	return render_template('delete.html')
	
@app.route('/remove',methods=['GET','POST'])
def remove():
	if 'loggedin' in session:
		if request.method == 'POST' :
			cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
			cursor.execute('SELECT * FROM accounts where id=%s',(session['id'],))
			account = cursor.fetchone()
			if account :
				session['id']=account['id']
				session['username'] = account['username']
				if request.form["LoginBtn1"]=="Yes":
					cursor.execute('DELETE from accounts where username= %s and id = %s',(session['username'],session['id'], ))
					mysql.connection.commit()
					return render_template('register.html',msg='account deleted')
				elif request.form["LoginBtn1"]=="No":
					return render_template('home.html')
			else :
				return redirect(url_for('login'))
	return redirect(url_for('login'))			
    
if __name__ == '__main__':
   app.run(debug=True)
	
