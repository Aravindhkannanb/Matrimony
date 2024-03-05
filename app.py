from flask import Flask,render_template,request,redirect,url_for,flash,session
import firebase_admin
from flask_pymongo import MongoClient
from firebase_admin import credentials, initialize_app, storage
import cv2
from flask_wtf import FlaskForm
from flask_bcrypt import Bcrypt
from wtforms import StringField, PasswordField, SubmitField, validators
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
uri = "mongodb+srv://aravindhkannan26:ir5gwMr4X3Y63IP0@matrimony.zv3ebwd.mongodb.net/?retryWrites=true&w=majority"
# Create a new client and connect to the server
client = MongoClient(uri)
# Send a ping to confirm a successful connection
try:
    client.admin.command('ping')
    print("Pinged your deployment. You successfully connected to MongoDB!")
except Exception as E:                                                                                                                                                         
    print(E)
app=Flask(__name__)
app.config['SECRET_KEY'] = 'abc'  # Replace 'your_secret_key' with a long, random string
bcrypt = Bcrypt(app)
cred = credentials.Certificate("serviceAccountKey.json")
initialize_app(cred, {'storageBucket': 'image-upload-2565a.appspot.com'})
db = client.get_database("Matrimony_detail")
payment = db["Payment"]
feedback_collection= db["Feedback"]
users_collection = db["Users"]  # Replace with your collection name
profile_collection=db["Profile"]
login_manager = LoginManager(app)
login_manager.login_view = 'login'


# Define the User model
class User(UserMixin):
    def __init__(self, user_id, username, email, password):
        self.id = user_id
        self.username = username
        self.email = email
        self.password = password

# Registration Form
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[validators.DataRequired(), validators.Length(min=2, max=20)])
    email = StringField('Email', validators=[validators.DataRequired(), validators.Email()])
    password = PasswordField('Password', validators=[validators.DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[validators.DataRequired(),
                                                                     validators.EqualTo('password', message='Passwords must match')])
    submit = SubmitField('Sign Up')



# Login Form
class LoginForm(FlaskForm):
    email = StringField('Email', validators=[validators.DataRequired(), validators.Email()])
    password = PasswordField('Password', validators=[validators.DataRequired()])
    submit = SubmitField('Login')
@login_manager.user_loader
def load_user(user_id):
    user_data = users_collection.find_one({"_id": user_id})
    if user_data:
        return User(user_data["_id"], user_data["username"], user_data["email"], user_data["password"])
    return None

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        username = form.username.data
        email = form.email.data
        password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')

        # Check if the user with the given email already exists
        existing_user = users_collection.find_one({"email": email})
        if existing_user:
            flash('Email address is already registered. Please use a different email.', 'danger')
            return redirect(url_for('register'))

        # Create a new user document in the MongoDB collection
        new_user = {
            "username": username,
            "email": email,
            "password": password
        }
        result = users_collection.insert_one(new_user)

        # Check if the user was successfully added to the database
        if result.inserted_id:
            flash('Your account has been created! You can now log in.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Error creating your account. Please try again later.', 'danger')

    return render_template('register.html', form=form)
@app.route('/', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        session['email']=email
        user_data = users_collection.find_one({"email": email})
        if user_data and bcrypt.check_password_hash(user_data["password"], password):
            user = User(user_data["_id"], user_data["username"], user_data["email"], user_data["password"])
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('main'))

        flash('Login unsuccessful. Please check your email and password.', 'danger')

    return render_template('login.html', form=form)



# Logout Route
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route("/payment",methods=["GET","POST"])
def home():
    
    if(request.method=='POST'):
        name=request.form.get('name')
        card=request.form.get("card")
        exp=request.form.get("exp")
        cvv=request.form.get("cvv")
        amount=request.form.get("amount")
        payment.insert_one({"name": name, "card": card, "exp": exp, "cvv": cvv, "amount": amount})
        return redirect(url_for("feedback"))
    return render_template('payment.html')
@app.route("/feedback",methods=["GET","POST"])
def feedback():
    if(request.method=="POST"):
        name=request.form.get('name')
        comment=request.form.get("comment")
        rating=request.form.get("rating")
        feedback_collection.insert_one({"name": name, "comment": comment,"rating":rating})
        return redirect(url_for("feedback"))
    return render_template("feedback.html")

@app.route("/profile",methods=["GET","POST"])
def profile():
    if(request.method=="POST"):
        name=request.form.get("name")
        email=request.form.get("email")
        contact=request.form.get('phone')
        address=request.form.get("address")
        family=request.form.get("family")
        qualify=request.form.get('education')
        salary=request.form.get("salary")
        religion=request.form.get("religion")
        file=request.form.get("file")
        profile_collection.insert_one({"name":name,"email":email,"contact":contact,"address":address,"family":family,"qualify":qualify,"salary":salary,"religion":religion})
        
        cam=cv2.VideoCapture(0)
        while True:
            ret,frame=cam.read()
            cv2.imshow("Face Image",frame)
            print(frame)
            if cv2.waitKey(100)&0xFF==ord("q"):
                break
            cv2.imwrite("{}.png".format(name),frame)
        
    
            
        fileName = "{}.png".format(name)
        bucket = storage.bucket()
        blob = bucket.blob("images/"+fileName)
        blob.upload_from_filename(fileName)
        blob.make_public()
        
        render_template("matrimoni.html")
    return render_template("matrimoni.html")

@app.route("/home",methods=["GET","POST"])
def main():
    print(session['email'])
    res = profile_collection.find_one({"email":session["email"]})
    print(res)
    return render_template("home.html",data=res)
@app.route('/update_user/<name>', methods=['GET', 'POST'])
def update_user(name):
    if(request.method=="POST"):
        email=request.form.get("email")
        contact=request.form.get('phone')
        address=request.form.get("address")
        family=request.form.get("family")
        qualify=request.form.get('education')
        salary=request.form.get("salary")
        religion=request.form.get("religion")
        profile_collection.update_one({"name":name},{"$set":{"email": email,
                "contact": contact,
                "address": address,
                "family": family,
                "education": qualify,
                "salary": salary,
                "religion": religion}})
        return redirect(url_for("main"))
    res = profile_collection.find_one({"name":name})
    return render_template('update_user.html', data=res)
@app.route("/view", methods=["GET", "POST"])
def view():
    res = profile_collection.find()
    bucket = storage.bucket()
    img = []

    for document in res:
        blob = bucket.blob('images/' + document['name'] + ".png")
        dict={"name":document['name'],"email":document['email'],"qualify":document['qualify'],"contact":document["contact"]}
        img.append(dict)
        blob.download_to_filename('F:\matrimonicode\matrimony\static\{}.png'.format(document['name']))
    print(img)
    return render_template("card.html", data=img)

if __name__=="__main__":
    app.run(port=5000,debug=True)