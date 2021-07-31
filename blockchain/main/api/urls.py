from django.urls import path
from main.api import views

urlpatterns = [
    path('nodes/', views.nodes),
    path('node/<str:ip_address>/', views.node),
    path('chain/', views.chain),
    path('store_block/', views.store_block),
    path('store_transaction/', views.store_transaction),
    path('last_block/', views.last_block),
    path('block/<str:block_hash>/', views.block),
    path('tx/<str:tx_hash>/', views.tx),
    path('tx_block/<str:block_hash>/', views.tx_block),
    path('tx_address/<str:address>/', views.tx_address),
    path('mempool/', views.mempool),
    path('coinbase_tx/', views.coinbase_tx),
    path('fee_tx/', views.fee_tx),
]
