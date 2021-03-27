from django.urls import path
from discord.views import *

urlpatterns = [
    path('commit/', CommitSendView.as_view(), name='index')
]
