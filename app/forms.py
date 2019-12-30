from wtforms_alchemy import ModelForm
from app.models import Computer, MacAddress

class MacAddressForm(ModelForm):
    class Meta:
        model = MacAddress

class ComputerForm(ModelForm):
    class Meta:
        model = Computer

