from django.urls import path
from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('sobre', views.sobre, name='sobre'),
    path('entrar', views.entrar, name='entrar'),
    path('cadastro', views.cadastro, name='cadastro'),
    path('sair', views.sair, name='sair'),
    path('apod', views.apod, name='apod'),
    path('activate/<uidb64>/<token>', views.activate, name='activate'),
]
