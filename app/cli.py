import getpass

import click
from flask import current_app
from flask.cli import with_appcontext

from .crypto import encrypt_field, hash_password
from .models import User, db
from .routes import EMAIL_CONTEXT


@click.command("init-db")
@with_appcontext
def init_db():
    db.create_all()
    click.echo("database ready")


@click.command("create-user")
@click.argument("username")
@click.argument("email")
@with_appcontext
def create_user(username, email):
    password = getpass.getpass("password: ")
    if getpass.getpass("repeat password: ") != password:
        raise click.ClickException("passwords do not match")
    if len(password) < 12:
        raise click.ClickException("password must be at least 12 characters")
    key = current_app.config["SETTINGS"].data_key
    user = User(
        username=username,
        password_hash=hash_password(password),
        email_encrypted=encrypt_field(key, email, EMAIL_CONTEXT),
    )
    db.session.add(user)
    db.session.commit()
    click.echo(f"user {username} created")


def register(app):
    app.cli.add_command(init_db)
    app.cli.add_command(create_user)
