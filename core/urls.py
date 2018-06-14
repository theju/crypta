from django.urls import path

from .views import (
    register_user, unregister_user, get_row, create_row,
    update_row, delete_row, export_rows,

    home_page, options, manifest
)

urlpatterns = [
    path('', home_page, name='index'),
    path('options/', options, name='options'),
    path('manifest.json', manifest, name='manifest'),

    path('get/', get_row, name='get_row'),
    path('post/', create_row, name='create_row'),
    path('update/', update_row, name='update_row'),
    path('delete/', delete_row, name='delete_row'),
    path('export/', export_rows, name='export_rows'),

    path('register/', register_user, name='register_user'),
    path('unregister/', unregister_user, name='unregister_user'),
]
