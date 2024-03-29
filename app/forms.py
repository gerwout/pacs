from wtforms_alchemy import ModelForm
from app.models import Computer, MacAddress
from flask_wtf import FlaskForm
from wtforms.fields import DateTimeLocalField
from wtforms import SubmitField, StringField, BooleanField
from wtforms.validators import InputRequired
from datetime import datetime

class MacAddressForm(ModelForm):
    class Meta:
        model = MacAddress

class ComputerForm(ModelForm):
    class Meta:
        model = Computer

class LogSearchForm(FlaskForm):
    current_date = datetime.now()
    start_date_time = DateTimeLocalField('Start', format='%Y-%m-%dT%H:%M:%S', validators=[InputRequired()])
    end_date_time = DateTimeLocalField('End', format='%Y-%m-%dT%H:%M:%S', validators=[InputRequired()])
    user = StringField("User")
    mac = StringField("MAC")
    ip = StringField("IP")
    logs_only = BooleanField("Only show compliance logs")
    submit = SubmitField('Search logs')
