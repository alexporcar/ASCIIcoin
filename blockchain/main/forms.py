from django import forms
from django.contrib.auth.forms import AuthenticationForm, UserCreationForm, PasswordChangeForm, ReadOnlyPasswordHashField
from django.core.exceptions import ValidationError
from main.models import MyUser, Transaction, Node
import main.utils as utils

class UserLoginForm(AuthenticationForm):
    def __init__(self, *args, **kwargs):
        super(UserLoginForm, self).__init__(*args, **kwargs)

    username = forms.EmailField(
        widget=forms.TextInput(attrs={
                'type': 'email',
                'class': 'form-control',
                'placeholder': 'name@example.com',
                'id': 'email'}
        )
    )
    password = forms.CharField(
        widget=forms.PasswordInput(attrs={
                'type': 'password',
                'class': 'form-control',
                'placeholder': 'password',
                'id': 'password'}
        )
    )

class MyUserCreationForm(UserCreationForm):
    password1 = forms.CharField(
        label='Password',
        widget=forms.PasswordInput(attrs={
                'type': 'password',
                'class': 'form-control',
                'placeholder': 'password'}
        ),
    )
    password2 = forms.CharField(
        label='Password confirmation',
        widget=forms.PasswordInput(attrs={
                'type': 'password',
                'class': 'form-control',
                'placeholder': 'password'}
        ),
    )

    class Meta:
        model = MyUser
        fields = ('email', 'password1', 'password2')

        widgets = {
            'email': forms.TextInput(attrs = {
                'type': 'email',
                'class': 'form-control',
                'placeholder': 'name@example.com'})
        }

    def save(self, commit=True):
        user = super().save(commit=False)
        user.set_address(self.cleaned_data['password1'])
        user.set_password(self.cleaned_data['password1'])
        if commit:
            user.save()
        return user

class UserChangeForm(forms.ModelForm):
    password = ReadOnlyPasswordHashField(
        label=('Password'),
        help_text=("Raw passwords are not stored, so there is no way to see this user's password."),
    )

    class Meta:
        model = MyUser
        fields = ('email', 'password', 'is_active', 'is_admin')

class PasswordsChangeForm(PasswordChangeForm):
    old_password = forms.CharField(
        widget=forms.PasswordInput(attrs={
                'type': 'password',
                'class': 'form-control',
                'placeholder': 'password'}
        )
    )
    new_password1 = forms.CharField(
        widget=forms.PasswordInput(attrs={
                'type': 'password',
                'class': 'form-control',
                'placeholder': 'password'}
        )
    )
    new_password2 = forms.CharField(
        widget=forms.PasswordInput(attrs={
                'type': 'password',
                'class': 'form-control',
                'placeholder': 'password'}
        )
    )

    class Meta:
        model = MyUser
        fields = ('old_password', 'new_password1', 'new_password2')

    def save(self, commit=True):
        user = super().save(commit=False)
        user.change_password(self.cleaned_data['old_password'], self.cleaned_data['new_password1'])
        if commit:
            user.save()
        return user

class SendTxForm(forms.ModelForm):
    error_messages = {
        'receiver': '',
        'balance': '',
        'password': 'Incorrect password.',
    }

    password = forms.CharField(
        widget=forms.PasswordInput(attrs={
                'type': 'password',
                'class': 'form-control',
                'placeholder': 'password'}
        )
    )

    class Meta:
        model = Transaction
        fields = ('receiver', 'amount', 'fee',)

        widgets = {
            'receiver': forms.TextInput(attrs = {
                'type': 'text',
                'class': 'form-control',
                'placeholder': 'receiver'}),
            'amount': forms.NumberInput(attrs = {
                'type': 'float',
                'class': 'form-control',
                'placeholder': 'amount'}),
            'fee': forms.NumberInput(attrs = {
                'type': 'text',
                'class': 'form-control',
                'placeholder': 'fee'}),
        }

class ConnectForm(forms.ModelForm):
    error_messages = {
        'port': 'The port number is invalid',
    }

    def clean_port(self):
        # checking the port
        port = self.cleaned_data.get('port')
        if type(port) == int:
            if port < 0 or port > 65535:
                raise forms.ValidationError(
                    self.error_messages['port'],
                    code='port',
                )
        return port

    class Meta:
        model = Node
        fields = ('ip_address', 'port',)

        widgets = {
            'ip_address': forms.TextInput(attrs = {
                'type': 'text',
                'class': 'form-control',
                'placeholder': 'ip_address'}),
            'port': forms.NumberInput(attrs = {
                'type': 'number',
                'class': 'form-control',
                'placeholder': 'port'})
        }