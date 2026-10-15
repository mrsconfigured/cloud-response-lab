"""Shuffle custom Python app adapter; API worker owns persistent dedup.

Copy into a reviewed Shuffle custom-app build with walkoff_app_sdk installed.
The SDK is deliberately not required for offline policy tests.
"""
import json
import ssl
import urllib.request
from walkoff_app_sdk.app_base import AppBase


class CloudResponseLab(AppBase):
    __version__ = '1.0.0'
    app_name = 'Cloud Response Lab'

    def triage_synthetic_alert(self, alert, api_token, ca_pem):
        if isinstance(alert, str):
            alert = json.loads(alert)
        context = ssl.create_default_context(cadata=ca_pem)
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *args, **kwargs):
                return None
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(), urllib.request.HTTPSHandler(context=context))
        request = urllib.request.Request('https://response:8443/respond', json.dumps(alert).encode(),
            headers={'Authorization': 'Bearer ' + api_token, 'Content-Type': 'application/json'}, method='POST')
        with opener.open(request, timeout=15) as response:
            return json.loads(response.read())


if __name__ == '__main__':
    CloudResponseLab.run()
