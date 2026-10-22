#!/usr/bin/env python3
"""Submit an environment credential to the already-open local authorizer only."""
import argparse
from html.parser import HTMLParser
import os
import urllib.error
import urllib.parse
import urllib.request


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class TokenForm(HTMLParser):
    def __init__(self):
        super().__init__()
        self.csrf = None
        self.token_field = False
        self.in_form = False

    def handle_starttag(self, tag, attributes):
        attrs = dict(attributes)
        if tag == 'form':
            self.in_form = attrs.get('action') == '/token' and attrs.get('method', '').lower() == 'post'
        if tag == 'input' and self.in_form:
            if attrs.get('name') == 'csrf':
                self.csrf = attrs.get('value')
            if attrs.get('name') == 'token' and attrs.get('type') == 'password':
                self.token_field = True

    def handle_endtag(self, tag):
        if tag == 'form':
            self.in_form = False


def submit(url):
    parsed = urllib.parse.urlsplit(url)
    if (parsed.scheme != 'http' or parsed.hostname != '127.0.0.1'
            or parsed.username or parsed.password or not parsed.port
            or parsed.path != '/' or parsed.query or parsed.fragment):
        raise ValueError('local_authorization_url_required')
    token = os.environ.pop('YANDEX_DISK_TOKEN', '')
    if not token or len(token) > 2048 or not all(c.isascii() and (c.isalnum() or c in '_-.') for c in token):
        raise ValueError('missing_or_invalid_environment_credential')
    opener = urllib.request.build_opener(NoRedirect())
    with opener.open(url, timeout=15) as response:
        page = response.read(32769)
        if len(page) > 32768:
            raise ValueError('unexpected_local_form')
    form = TokenForm()
    form.feed(page.decode('utf-8'))
    if not form.token_field or not form.csrf:
        raise ValueError('unexpected_local_form')
    origin = f'http://127.0.0.1:{parsed.port}'
    body = urllib.parse.urlencode({'csrf': form.csrf, 'token': token}).encode()
    request = urllib.request.Request(origin+'/token', data=body,
                                     headers={'Origin': origin, 'Content-Type': 'application/x-www-form-urlencoded'})
    with opener.open(request, timeout=15) as response:
        if response.status != 200:
            raise ValueError('local_form_rejected')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--url', required=True)
    args = parser.parse_args()
    try:
        submit(args.url)
        print('TOKEN_FORM_RESULT=accepted', flush=True)
    except Exception as exc:
        print('TOKEN_FORM_RESULT=failed_'+type(exc).__name__, flush=True)
        raise SystemExit(1) from None
