from django.http import HttpResponse

from django.utils.decorators import method_decorator
from django.utils.encoding import force_bytes

from django.views.decorators.http import require_POST
from django.views.decorators.csrf import csrf_exempt
from django.views.generic import View

from django.conf import settings

from ipaddress import ip_address, ip_network
import requests
import hmac
from hashlib import sha1


@method_decorator(require_POST, name='dispatch')
@method_decorator(csrf_exempt, name='dispatch')
class CommitSendView(View):
    def post(self, request):
        if self.__check_manager(request):
            return HttpResponse(status=200)
        return HttpResponse('Access denied', status=403)

    def __check_manager(self, request):
        if self.__is_valid_ip(ip_address(u'{}'.format(request.META.get('HTTP_X_FORWARDED_FOR')))):
            head_signature = request.META.get('HTTP_X_HUB_SIGNATURE')
            if self.__is_valid_head_signature(head_signature):
                hash_name, signature = head_signature.split('=')
                if self.__is_valid_hash_name(hash_name):
                    mac = hmac.new(force_bytes(settings.GITHUB_SECRET_KEY), msg=force_bytes(request.body), digestmod=sha1)
                    if self.__hmac_checker(mac, signature):
                        return True
        return False

    def __is_valid_ip(self, ip):
        whitelist = requests.get('https://api.github.com/meta').json()['hooks']
        return any(map(lambda x: ip in ip_network(x), whitelist))

    def __is_valid_head_signature(self, signature):
        return True if signature is not None else False

    def __is_valid_hash_name(self, name):
        return True if name == 'sha1' else False

    def __hmac_checker(self, mac, signature):
        return True if hmac.compare_digest(force_bytes(mac.hexdigest()), force_bytes(signature)) else False


