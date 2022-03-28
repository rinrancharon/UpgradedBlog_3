from flask import Flask, render_template, redirect, url_for, flash, abort
from functools import wraps
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Table, Column, Integer, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterUserForm, LoginUserForm, CommentForm
from flask_gravatar import Gravatar

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
app.config['WEB_CONCURRENCY'] = 3
ckeditor = CKEditor(app)
Bootstrap(app)

base = declarative_base()

login_manager = LoginManager()
login_manager.init_app(app)

# #CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


# #CONFIGURE TABLES
class User(UserMixin, db.Model):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(250), nullable=False)
    email = db.Column(db.String(250), nullable=False, unique=True)
    password = db.Column(db.String(250), nullable=False)

    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="commenter")


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)

    author_id = db.Column(db.Integer, ForeignKey("user.id"))
    author = relationship("User", back_populates="posts")
    comments_blog = relationship("Comment", back_populates="blogpost")


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(250), nullable=False)

    blogpost_id = db.Column(db.Integer, ForeignKey("blog_posts.id"))
    blogpost = relationship("BlogPost", back_populates="comments_blog")
    commenter_id = db.Column(db.Integer, ForeignKey("user.id"))
    commenter = relationship("User", back_populates="comments")

# db.create_all()


def admin_only(f):
    @wraps(f)
    def wrapper_function(*args, **kwargs):
        # if id is not 1 then return abort 403 error
        if not current_user.is_authenticated or current_user.id != 1:
            return abort(403)
        #else continue with the route function
        return f(*args, **kwargs)
    return wrapper_function


@login_manager.user_loader
def load_user(id):
    return User.query.get(id)


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts)


@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterUserForm()

    if form.validate_on_submit():
        newUser_email = form.email.data
        newUser_username = form.username.data
        checkUser_email = db.session.query(User).filter_by(email=newUser_email).one_or_none()
        checkUser_username = db.session.query(User).filter_by(username=newUser_username).one_or_none()

        if checkUser_email:
            flash("The email is already registered. Login instead!!")
            return redirect(url_for("login"))

        elif checkUser_username:
            flash("The username is already taken.")
            return redirect(url_for("register"))

        else:
            if form.password.data == form.retype_password.data:

                newUser_password = generate_password_hash(form.password.data, method="pbkdf2:sha256", salt_length=16)

                newUser = User(username=newUser_username, email=newUser_email, password=newUser_password)

                db.session.add(newUser)
                db.session.commit()

                login_user(newUser)

                return redirect(url_for("get_all_posts"))

    return render_template("register.html", form=form)


@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginUserForm()

    if form.validate_on_submit():

        loginUser_email = form.email.data
        loginUser = db.session.query(User).filter_by(email=loginUser_email).one_or_none()

        if loginUser:
            loginUser_password = form.password.data
            token_password = check_password_hash(loginUser.password, loginUser_password)

            if token_password:

                login_user(loginUser)
                return redirect(url_for("get_all_posts"))

            else:
                flash("Incorrect password")
                return redirect(url_for("login"))

        else:
            flash("User doesn't exist. Register now!!")
            return redirect(url_for("login"))

    return render_template("login.html", form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
@login_required
def show_post(post_id):
    form = CommentForm()
    requested_post = BlogPost.query.get(post_id)

    comment_list = Comment.query.filter_by(blogpost_id=requested_post.id).all()

    if form.validate_on_submit():
        if current_user is None:
            flash("Please login to comment.")
            return redirect(url_for("login"))
        else:
            comment = Comment(text=form.comment.data, commenter=current_user, blogpost=requested_post)
            db.session.add(comment)
            db.session.commit()
            return redirect(url_for("get_all_posts"))

    return render_template("post.html", post=requested_post, comments=comment_list, form=form)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>")
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(debug=True)
