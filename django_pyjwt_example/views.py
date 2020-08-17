from django.contrib.auth import get_user_model
from rest_framework import viewsets
from django_pyjwt_example import serializers


class UserViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = get_user_model().objects.all()
    serializer_class = serializers.UserSerializer
