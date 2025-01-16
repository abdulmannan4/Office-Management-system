from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from .serializers import UserRegistrationSerializer
from .utils import get_tokens_for_user, send_email
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import force_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from rest_framework import status
from django.contrib.auth.models import User
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.tokens import RefreshToken

def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)
    return {
        'access': str(refresh.access_token),
        'refresh': str(refresh)
    }

def verify_email(email):
    try:
        User = get_user_model()
        user = User.objects.get(email=email)
        uid = urlsafe_base64_encode(force_bytes(user.id))
        token = PasswordResetTokenGenerator().make_token(user)
        link = f'http://localhost:3000/verify-email/{uid}/{token}/'

        body = f'Click the following link to verify your account: {link}'
        data = {
            'subject': 'Verify your email',
            'body': body,
            'to_email': user.email
        }
        send_email(data)
        return Response({'msg': 'Verification email sent'}, status=status.HTTP_200_OK)
    except User.DoesNotExist:
        return Response({'msg': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny
from rest_framework import status

class UserRegistrationView(APIView):
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        serializer = UserRegistrationSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            print(user.email)
            verify_email(user.email)
            token = get_tokens_for_user(user)
            return Response({
                'token': token,
                'msg': 'Registration successful. Please verify your email.'
            }, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from django.utils.http import urlsafe_base64_decode
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from api.models import User

class SendVerifyEmailView(APIView):
    def get(self, request, uidb64, token, format=None):
        try:
            uid = urlsafe_base64_decode(uidb64).decode()
            user = User.objects.get(id=uid)
            token_generator = PasswordResetTokenGenerator()
            if token_generator.check_token(user, token):
                user.is_active = True 
                user.verified = True 
                user.save()
                return Response({'msg': 'Email Verified'}, status=status.HTTP_200_OK)
            else:
                return Response({'msg': 'Invalid token or link expired'}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'msg': f'Error: {str(e)}'}, status=status.HTTP_400_BAD_REQUEST)
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth import authenticate, login
from django.http import JsonResponse
from .serializers import UserLoginSerializer
from .utils import get_tokens_for_user
from rest_framework.permissions import AllowAny
class UserLoginView(APIView):
    permission_classes = [AllowAny]
    def post(self, request, format=None):
 
        serializer = UserLoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)  
        email = serializer.data.get('email')
        password = serializer.data.get('password')
        user = authenticate(request, email=email, password=password)

        if user is not None:
            login(request, user)
            token = get_tokens_for_user(user)
            response = JsonResponse({'msg': 'Login Success'})
            response.set_cookie(key='access', value=token['access'], secure=True, samesite='Lax', max_age=50)  # not HttpOnly
            response.set_cookie(key='refresh', value=token['refresh'], secure=True, samesite='Lax', max_age=3600 * 24 * 7)  # not HttpOnly

            return response
        else:
            return Response({'errors': {'non_field_errors': ['Invalid email or password']}}, status=status.HTTP_401_UNAUTHORIZED)

class TokenRefreshViewO(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        refresh_token = request.COOKIES.get('refresh')
        print(refresh_token)
        if not refresh_token:
            return Response({'error': 'Refresh token required'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            refresh = RefreshToken(refresh_token)
            new_access_token = str(refresh.access_token)
            response = Response({
                'access': new_access_token,
                
            }, status=status.HTTP_200_OK)
            response.set_cookie('access', new_access_token)
            print('new token mil gia access')
            return response
        except TokenError:
            return Response({'error': 'Invalid refresh token'}, status=status.HTTP_400_BAD_REQUEST)

             
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView

class UserView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        if not request.user.is_authenticated:
            return Response({'error': 'User is not authenticated'}, status=status.HTTP_401_UNAUTHORIZED)
        msg = f'Hello {request.user.username}'
        user_data = {
            'username': request.user.username,
            'email': request.user.email,
            'first_name': request.user.first_name,
            'last_name': request.user.last_name,
            'msg':msg
        }
        return Response(user_data, status=status.HTTP_200_OK)

             
            
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth import logout
class Logout(APIView):
    permission_classes = [AllowAny]
    
    def get(self, request):
        access_token = request.COOKIES.get('access')
        refresh_token = request.COOKIES.get('refresh')
        print(access_token)
        print(refresh_token)
        logout(request)
        response = Response({'message': 'Logged out successfully.'}, status=status.HTTP_200_OK)
        
        if access_token:
            response.delete_cookie('access')
        if refresh_token:
            response.delete_cookie('refresh')

        if not access_token and not refresh_token:
       
            return Response({'message': 'No cookies found to delete.'}, status=status.HTTP_400_BAD_REQUEST)

        return response

    
             
 
             
             
             
             
             
             
             
             
             
             
             # from rest_framework.response import Response
# from rest_framework import status
# from rest_framework.views import APIView

# from rest_framework.permissions import IsAuthenticated
# from django.contrib.auth import authenticate
# from .serializers import UserRegistrationSerializer, UserLoginSerializer
# from django.contrib.auth.tokens import PasswordResetTokenGenerator
# from django.utils.encoding import force_bytes, DjangoUnicodeDecodeError
# from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
# from .utils import get_tokens_for_user, send_email
# from api.models import User

# # Verify email and send verification email to user
# def verify_email(email):
#     try:
#         user = User.objects.get(email=email)
#         uid = urlsafe_base64_encode(force_bytes(user.id))
#         print('Encoded UID:', uid)
#         token = PasswordResetTokenGenerator().make_token(user)
#         print('Password Reset Token:', token)
#         link = f'http://localhost:3000/verify-email/{uid}/{token}/'
#         print('Verify Link:', link)

#         # Send email
#         body = f'Click the following link to verify your account: {link}'
#         data = {
#             'subject': 'Verify your email',
#             'body': body,
#             'to_email': user.email
#         }
#         send_email(data)
#         return Response({'msg': 'Verification email sent'}, status=status.HTTP_200_OK)
#     except User.DoesNotExist:
#         return Response({'msg': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

# # User Registration View
# class UserRegistrationView(APIView):
#     def post(self, request, format=None):
#         serializer = UserRegistrationSerializer(data=request.data)
#         if serializer.is_valid():
#             user = serializer.save() 
#             token = get_tokens_for_user(user) 
#             print('success registered backend and sent token')
#             verify_email(user.email)
#             return Response({
#                 'token': token,
#                 'msg': 'Registration Success'
#             }, status=status.HTTP_201_CREATED)
#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# # Send Verification Email View
# class SendVerifyEmailView(APIView):
#     def get(self, request, uidb64, token, format=None):
#         try:
#             uid = urlsafe_base64_decode(uidb64).decode()
#             user = User.objects.get(id=uid)

#             # Validate the token
#             token_generator = PasswordResetTokenGenerator()
#             if token_generator.check_token(user, token):
#                 # If the token is valid, activate the user
#                 user.is_active = True
#                 user.verified=True
#                 user.save()
#                 return Response({'msg': 'Email Verified'}, status=status.HTTP_200_OK)
#             else:
#                 return Response({'msg': 'Invalid token or link expired'}, status=status.HTTP_400_BAD_REQUEST)
#         except Exception as e:
#             return Response({'msg': f'Error: {str(e)}'}, status=status.HTTP_400_BAD_REQUEST)

# # User Login View
# class UserLoginView(APIView):
#     def post(self, request, format=None):
#         serializer = UserLoginSerializer(data=request.data)
#         serializer.is_valid(raise_exception=True)

#         email = serializer.data.get('email')
#         password = serializer.data.get('password')

#         # Authenticate the user
#         user = authenticate(email=email, password=password)

#         if user is not None:
#             # Generate JWT tokens
#             token = get_tokens_for_user(user)

#             response = Response({'msg': 'Login Success'}, status=status.HTTP_200_OK)
#             response.set_cookie(key='access', value=token['access'], httponly=True, secure=True, samesite='Strict', max_age=3600)
#             response.set_cookie(key='refresh', value=token['refresh'], httponly=True, secure=True, samesite='Strict', max_age=3600*24*7)

#             return response
#         else:
#             return Response({'errors': {'non_field_errors': ['Invalid email or password']}}, status=status.HTTP_401_UNAUTHORIZED)