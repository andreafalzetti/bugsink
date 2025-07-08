from django.conf import settings
from django.core.exceptions import DisallowedHost
from django.http import HttpRequest
from django.utils.http import split_domain_port

from .cidr_utils import is_host_allowed


class CIDRHostValidationMiddleware:
    """
    Middleware that extends Django's ALLOWED_HOSTS validation to support CIDR notation.
    
    This middleware should be placed before Django's CommonMiddleware in the
    MIDDLEWARE setting to override the default host validation.
    """
    
    def __init__(self, get_response):
        self.get_response = get_response
    
    def __call__(self, request: HttpRequest):
        # Validate the host header
        host = request.get_host()
        
        # Split domain and port
        domain, port = split_domain_port(host)
        
        # Check if the host is allowed
        if not is_host_allowed(domain, settings.ALLOWED_HOSTS):
            raise DisallowedHost(f"Invalid HTTP_HOST header: '{host}'. You may need to add '{domain}' to ALLOWED_HOSTS.")
        
        return self.get_response(request)