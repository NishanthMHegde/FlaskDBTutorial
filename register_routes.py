from flask import render_template, request, redirect, url_for
from models import Person
from models import User
from flask_login import login_user, logout_user, current_user, login_required

def register_routes(db, app, bcrypt):
    @app.route('/', methods=['GET', 'POST'])
    def index():
        if request.method == 'GET':
            people = Person.query.all()
            if current_user.is_authenticated:
                user = str(current_user.username)
            else:
                user = "Not logged in"
            return render_template(template_name_or_list = 'index.html', people=people, user=user)
        elif request.method == 'POST':
            name = request.form.get('name')
            age = int(request.form.get('age'))
            job = request.form.get('job')
            person = Person(name=name, age=age, job=job)
            db.session.add(person)
            db.session.commit()
            people = Person.query.all()
            return redirect(url_for('index'))


    @app.route('/delete/<pid>', methods=['DELETE'])
    def delete_person(pid):
        Person.query.filter(Person.pid == pid).delete()
        db.session.commit()
        people = Person.query.all()
        return render_template(template_name_or_list = 'index.html', people=people)

    @app.route('/signup', methods=['POST', 'GET'])
    def signup():
        if request.method == 'GET':
            return render_template(template_name_or_list = 'signup.html')
        elif request.method == 'POST':
            username = request.form.get('username')
            password = request.form.get('password')
            role = request.form.get('role')
            description = request.form.get('description')
            hashed_password = bcrypt.generate_password_hash(password)
            user = User(username=username, password=hashed_password, role=role, description=description)
            db.session.add(user)
            db.session.commit()
            return redirect(url_for('index'))

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if request.method == 'GET':
            return render_template(template_name_or_list = 'login.html')
        elif request.method == 'POST':
            username = request.form.get('username')
            password = request.form.get('password')
            user = User.query.filter(User.username==username).first()
            if user:
                if bcrypt.check_password_hash(user.password, password):
                    login_user(user)
                    return redirect(url_for('index'))
                else:
                    return "Log In Failed. Please check your username and password"
            else:
                return "Log In Failed. Please check your username and password"
        
            

    @app.route('/logout')
    def logout():
        logout_user()
        return "Logged out!"

    
    