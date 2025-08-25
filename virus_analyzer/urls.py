from django.contrib import admin
from django.urls import path
from vt_analyzer import views
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', views.analyze, name='home'),  # Changed from analyze_view to analysis_view
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
