from flask_wtf import FlaskForm
from flask import flash, redirect, url_for
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo, ValidationError
from models_mongo import User

class RegistrationForm(FlaskForm):
    email = StringField('Email: ', validators=[DataRequired(), Email()])
    password = PasswordField('Password: ', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password: ',
                                     validators=[DataRequired(), EqualTo('password', message='Passwords must match. Please try again.')])
    submit = SubmitField('Register')

    def validate_email(self, email):
        user = User.objects(email=email.data).first()
        if user:
            flash(f'Not successful validation, recheck your entry. Either the email is already registered or the passwords do not match.', 'danger')
            raise ValidationError('That email is already taken. Please choose a different one.')
class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')


class SendEthForm(FlaskForm):
    to_address = StringField('To Address', validators=[DataRequired()])
    amount_eth = StringField('Amount of ETH', validators=[DataRequired()])
    gas_price_gwei = StringField('Maximum Gas Price in Gwei', validators=[DataRequired()])
    submit = SubmitField('Send ETH')
