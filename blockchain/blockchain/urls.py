from django.urls import include, path
from rest_framework import routers
from main import views

urlpatterns = [
    path('', include('main.urls')),
    path('api/', include('main.api.urls')),
    path('api-auth/', include('rest_framework.urls', namespace='rest_framework')),
]
