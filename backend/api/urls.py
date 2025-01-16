# from django.urls import path
# from . import views
# from rest_framework_simplejwt.views import (
#     TokenObtainPairView,
#     TokenRefreshView,TokenVerifyView
# )

# urlpatterns = [
    
#     path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
#    
#      path('api/token/verify/', TokenVerifyView.as_view(), name='token_verify'),
# ]

from django.urls import path
from api.views import UserRegistrationView,UserLoginView,SendVerifyEmailView,UserView,TokenRefreshViewO,Logout

urlpatterns = [
    path('register/', UserRegistrationView.as_view(), name='register'),
    path('logout/', Logout.as_view(), name='logout'),
    
   
    
    path('login/',UserLoginView.as_view(),name="login"),
    path('token/refresh/', TokenRefreshViewO.as_view(), name='token_refresh'),
   path('user/', UserView.as_view(), name='user_view'),
       path('verify-email/<uidb64>/<token>/', SendVerifyEmailView.as_view(), name='send-reset-password-email'),
       
     

]