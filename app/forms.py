from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, TextAreaField, BooleanField
from wtforms import validators

class LookupForm(FlaskForm):
    do_dns_reverse_lookup = BooleanField('Do reverse DNS Lookup:')
    ip_address = TextAreaField('ip_address', validators=[validators.DataRequired(), validators.length(max=1024)])
    btn_lookup = SubmitField(label='Lookup IP')

class AutoproxyLookupForm(FlaskForm):
    myip = TextAreaField('myip', validators=[validators.DataRequired(), validators.length(max=1024)])
    url = StringField('url', validators=[validators.DataRequired(), validators.length(max=1024)])
    btn_lookup = SubmitField(label='Lookup Autoproxy')
