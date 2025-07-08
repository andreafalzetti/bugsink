"""
WSGI config for bugsink project.

It exposes the WSGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/4.2/howto/deployment/wsgi/
"""

import os

import django

from django.core.handlers.wsgi import WSGIHandler, WSGIRequest
from django.core.exceptions import DisallowedHost
from django.utils.http import split_domain_port

from .cidr_utils import is_host_allowed

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'bugsink_conf')


class CustomWSGIRequest(WSGIRequest):
    """
    Custom WSQIRequest subclass with 2 fixes:

    * Chunked Transfer Encoding (Django's behavior is broken)
    * Better error message for disallowed hosts

    Note: used in all servers (in gunicorn through wsgi.py; in Django's runserver through WSGI_APPLICATION)
    """

    def __init__(self, environ):
        """
        We override this method to fix Django's behavior in the context of Chunked Transfer Encoding (Django's
        behavior, behind Gunicorn, is broken). Django's breakage is in the super() of this method, in the combination
        [1] defaulting (through a set-on-catch) to 0 for CONTENT_LENGTH when not present and [2] settings self._stream
        to a LimitedStream with that length. The lines below undo this behavior iff the HTTP_TRANSFER_ENCODING header
        is present. See:
        * https://code.djangoproject.com/ticket/35838   (The Django problem)
        * https://github.com/bugsink/bugsink/issues/9   (Why we need a fix)
        """
        super().__init__(environ)

        if "CONTENT_LENGTH" not in environ and "HTTP_TRANSFER_ENCODING" in environ:
            self._stream = self.environ["wsgi.input"]

    def get_host(self):
        """
        We override this method to:
        1. Support CIDR notation in ALLOWED_HOSTS
        2. Provide a more informative error message when the host is disallowed
        
        This method replaces Django's default host validation with our CIDR-aware validation.
        """

        # Import pushed down to make it absolutely clear we avoid circular importing/loading the wrong thing:
        from django.conf import settings
        
        # Get the raw host value using Django's logic but without validation
        # This code is adapted from django.http.request.HttpRequest.get_host()
        host = self.META.get('HTTP_X_FORWARDED_HOST')
        if not host:
            host = self.META.get('HTTP_HOST')
        if not host:
            # Reconstruct the host using the server variables
            server_name = self.META.get('SERVER_NAME')
            server_port = str(self.META.get('SERVER_PORT', '80'))
            if server_port != ('443' if self.is_secure() else '80'):
                host = '%s:%s' % (server_name, server_port)
            else:
                host = server_name
        
        # Extract domain without port for validation
        domain, port = split_domain_port(host)
        
        # Get allowed hosts
        allowed_hosts = settings.ALLOWED_HOSTS
        if settings.DEBUG and not allowed_hosts:
            allowed_hosts = [".localhost", "127.0.0.1", "[::1]"]
        
        # Validate using our CIDR-aware function
        if not is_host_allowed(domain, allowed_hosts):
            msg = "Invalid HTTP_HOST header: %r." % host
            if domain:
                msg += " You may need to add %r to ALLOWED_HOSTS." % domain
            msg += " Current ALLOWED_HOSTS: %s" % repr(allowed_hosts)
            raise DisallowedHost(msg)
        
        return host


class CustomWSGIHandler(WSGIHandler):
    request_class = CustomWSGIRequest


def custom_get_wsgi_application():
    # Like get_wsgi_application, but returns a subclass of WSGIHandler that uses a custom request class.
    django.setup(set_prefix=False)
    return CustomWSGIHandler()


application = custom_get_wsgi_application()
