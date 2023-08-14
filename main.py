from datetime import date
from flask import Flask, abort, render_template, redirect, url_for, flash, request, g
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from flask_gravatar import Gravatar
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user, login_required
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.orm import relationship
# Import your forms from the forms.py
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm


'''
Make sure the required packages are installed: 
Open the Terminal in PyCharm (bottom left). 

On Windows type:
python -m pip install -r requirements.txt

On MacOS type:
pip3 install -r requirements.txt

This will install the packages from the requirements.txt for this project.
'''

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap5(app)

login_manager = LoginManager()

login_manager.init_app(app)


# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///posts.db'
db = SQLAlchemy()
db.init_app(app)


gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)



class User(UserMixin, db.Model):
    __table__name = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))

    posts = db.relationship("BlogPost", back_populates = 'post_author')
    comments = db.relationship("Comment", back_populates = 'comment_author')


# CONFIGURE TABLES
class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    img_url = db.Column(db.String(250), nullable=False)

    post_author = db.relationship("User", back_populates='posts')
    comments = db.relationship("Comment",back_populates='parent_post')

class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.String(250), nullable=False)
    text = db.Column(db.Text, nullable=False)
    commentor_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    post_id = db.Column(db.Integer, db.ForeignKey('blog_posts.id'))

    parent_post = db.relationship("BlogPost", back_populates = 'comments')
    comment_author = db.relationship("User", back_populates='comments')


# TODO: Create a User table for all your registered users. 




with app.app_context():
    db.create_all()


@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)



def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):

        if current_user.id != 1:
                abort(403)
        else:
             return f(*args, **kwargs)

    return decorated_function



# TODO: Use Werkzeug to hash the user's password when creating a new user.
@app.route('/register', methods = ['GET','POST'])
def register():
    form = RegisterForm()

    if request.method == 'POST':
        name = form.name.data
        email = form.email.data
        result = db.session.execute(db.select(User).where(User.email == email)).scalar()
        if result:
            flash('Email already exists! Try again!')
            return render_template("register.html",form = form)

        hashed = generate_password_hash(request.form['password'], method = 'pbkdf2:sha256', salt_length=8)

        new_user = User(
            name = name,
            email = email,
            password = hashed
        )

        db.session.add(new_user)
        db.session.commit()

        login_user(new_user)

        return render_template("index.html")

    return render_template("register.html", form=form)


# TODO: Retrieve a user from the database based on their email. 
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    email = form.email.data
    password = form.password.data

    if request.method == 'POST':

        try:
            result = db.session.execute(db.select(User).where(User.email == email))
            user_to_check = result.scalar()
            password_to_check = user_to_check.password

            if check_password_hash(password_to_check,password):
                login_user(user_to_check)
                return redirect(url_for('get_all_posts'))
            else:
                flash('Invalid Password', category='error')
                return render_template("login.html", form = form)

        except AttributeError:
            flash('No user email found', category='error')

    return render_template("login.html", form = form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route('/')
def get_all_posts():
    result = db.session.execute(db.select(BlogPost))
    posts = result.scalars().all()
    return render_template("index.html", all_posts=posts)


# TODO: Allow logged-in users to comment on posts
@app.route("/post/<int:post_id>", methods = ['GET','POST'])
def show_post(post_id):
    requested_post = db.get_or_404(BlogPost, post_id)
    form = CommentForm()


    if form.validate_on_submit():
        if current_user.is_authenticated:
            comment = Comment(
                date = date.today().strftime("%B %d, %Y"),
                text = form.comment.data,
                comment_author = current_user,
                parent_post = requested_post
            )
            db.session.add(comment)
            db.session.commit()
        else:
            flash('You are not logged in. Login to submit comments',category=403)
            return redirect(url_for('login'))
    results = db.session.execute(db.select(Comment).where(Comment.post_id == post_id))
    comments = results.scalars().all()



    return render_template("post.html", post=requested_post, form=form, comments = comments)


# TODO: Use a decorator so only an admin user can create a new post
@app.route("/new-post", methods=["GET", "POST"])
@admin_required
def add_new_post():
    print(current_user.id)
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            post_author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


# TODO: Use a decorator so only an admin user can edit a post
@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_required
def edit_post(post_id):
    post = db.get_or_404(BlogPost, post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        post_author=post.post_author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = current_user
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))
    return render_template("make-post.html", form=edit_form, is_edit=True)



# TODO: Use a decorator so only an admin user can delete a post
@app.route("/delete/<int:post_id>")
@admin_required
def delete_post(post_id):
    post_to_delete = db.get_or_404(BlogPost, post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


if __name__ == "__main__":
    app.run(debug=True, port=5002)
