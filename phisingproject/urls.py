from django.contrib import admin
from django.urls import path
from .views import predict

urlpatterns = [
    path('admin/', admin.site.urls),
    path('predict/', predict, name='predict'),  # Ensure you include this
]
