from django.urls import path
from django.contrib import admin
from django.contrib.auth import views as auth_views
from main.forms import UserLoginForm, PasswordsChangeForm
from blockchain import settings
from main import views

urlpatterns = [
    path('', views.home, name='home'),
    path('admin/', admin.site.urls, name='admin'),
    path('login/', auth_views.LoginView.as_view(template_name='main/account/login.html', authentication_form=UserLoginForm), name='login'),
    path('register/', views.register, name='register'),
    path('password/', auth_views.PasswordChangeView.as_view(template_name='main/account/password.html', form_class=PasswordsChangeForm, success_url='/success/'), name='password'),
    path('success/', views.success, name='success'),
    path('export/', views.export, name='export'),
    path('logout/', auth_views.LogoutView.as_view(next_page=settings.LOGOUT_REDIRECT_URL), name='logout'),
    path('account/', views.account, name='account'),
    path('explorer/', views.explorer, name='explorer'),
    path('chain/', views.blocks, name='chain'),
    path('block/<str:block_hash>/', views.block, name='block'),
    path('transactions/', views.transactions, name='transactions'),
    path('tx/<str:tx_hash>/', views.tx, name='tx'),
    path('address/<str:address>/', views.address, name='address'),
    path('send/', views.send, name='send'),
    path('connect/', views.connect, name='connect'),
    path('sync/', views.sync, name='sync'),
    path('mine/', views.mine, name='mine'),
]
