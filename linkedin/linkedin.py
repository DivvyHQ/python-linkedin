# -*- coding: utf-8 -*-
from __future__ import unicode_literals
import collections
import contextlib
import hashlib
import random

try:
    from urllib.parse import quote, quote_plus
except ImportError:
    from urllib import quote, quote_plus

import requests
from requests_oauthlib import OAuth1

from .exceptions import LinkedInError
from .utils import enum, to_utf8, raise_for_error, json, StringIO


__all__ = ['LinkedInAuthentication', 'LinkedInApplication', 'PERMISSIONS']

AccessToken = collections.namedtuple('AccessToken', ['access_token', 'expires_in'])

PERMISSIONS = enum('Permission',
                   ORG_ADMIN='rw_organization_admin',
                   ORG_SOCIAL='w_organization_social',
                   LITE_PROFILE='r_liteprofile',
                   MEMBER_SOCIAL='w_member_social')

ENDPOINTS = enum('LinkedInURL',
                 ME_V2='https://api.linkedin.com/v2/me',
                 COMPANIES_V2='https://api.linkedin.com/v2/organizationalEntityAcls?q=roleAssignee',
                 UGC_POSTS_V2='https://api.linkedin.com/v2/ugcPosts',
                 IMAGE_UPLOAD_V2='https://api.linkedin.com/v2/assets?action=registerUpload'),

class LinkedInDeveloperAuthentication(object):
    """
    Uses all four credentials provided by LinkedIn as part of an OAuth 1.0a
    flow that provides instant API access with no redirects/approvals required.
    Useful for situations in which users would like to access their own data or
    during the development process.
    """

    def __init__(self, consumer_key, consumer_secret, user_token, user_secret,
                 redirect_uri, permissions=[]):
        self.consumer_key = consumer_key
        self.consumer_secret = consumer_secret
        self.user_token = user_token
        self.user_secret = user_secret
        self.redirect_uri = redirect_uri
        self.permissions = permissions


class LinkedInAuthentication(object):
    """
    Implements a standard OAuth 2.0 flow that involves redirection for users to
    authorize the application to access account data.
    """
    AUTHORIZATION_URL = 'https://www.linkedin.com/uas/oauth2/authorization'
    ACCESS_TOKEN_URL = 'https://www.linkedin.com/uas/oauth2/accessToken'

    def __init__(self, key, secret, redirect_uri, permissions=None):
        self.key = key
        self.secret = secret
        self.redirect_uri = redirect_uri
        self.permissions = permissions or []
        self.state = None
        self.authorization_code = None
        self.token = None
        self._error = None

    @property
    def authorization_url(self):
        qd = {'response_type': 'code',
              'client_id': self.key,
              'scope': (' '.join(self.permissions)).strip(),
              'state': self.state or self._make_new_state(),
              'redirect_uri': self.redirect_uri}
        # urlencode uses quote_plus when encoding the query string so,
        # we ought to be encoding the qs by on our own.
        qsl = ['%s=%s' % (quote(k), quote(v)) for k, v in qd.items()]
        return '%s?%s' % (self.AUTHORIZATION_URL, '&'.join(qsl))

    @property
    def last_error(self):
        return self._error

    def _make_new_state(self):
        return hashlib.md5(
            '{}{}'.format(random.randrange(0, 2 ** 63), self.secret).encode("utf8")
        ).hexdigest()

    def get_access_token(self, timeout=60):
        assert self.authorization_code, 'You must first get the authorization code'
        qd = {'grant_type': 'authorization_code',
              'code': self.authorization_code,
              'redirect_uri': self.redirect_uri,
              'client_id': self.key,
              'client_secret': self.secret}
        response = requests.post(self.ACCESS_TOKEN_URL, data=qd, timeout=timeout)
        raise_for_error(response)
        response = response.json()
        self.token = AccessToken(response['access_token'], response['expires_in'])
        return self.token


class LinkedInSelector(object):
    @classmethod
    def parse(cls, selector):
        with contextlib.closing(StringIO()) as result:
            if type(selector) == dict:
                for k, v in selector.items():
                    result.write('%s:(%s)' % (to_utf8(k), cls.parse(v)))
            elif type(selector) in (list, tuple):
                result.write(','.join(map(cls.parse, selector)))
            else:
                result.write(to_utf8(selector))
            return result.getvalue()


class LinkedInApplication(object):
    def __init__(self, authentication=None, token=None):
        assert authentication or token, 'Either authentication instance or access token is required'
        self.authentication = authentication
        if not self.authentication:
            self.authentication = LinkedInAuthentication('', '', '')
            self.authentication.token = AccessToken(token, None)

    def make_request(self, method, url, data=None, params=None, headers=None,
                     timeout=60):
        if headers is None:
            headers = {'x-li-format': 'json', 'Content-Type': 'application/json'}
        else:
            headers.update({'x-li-format': 'json', 'Content-Type': 'application/json'})

        if params is None:
            params = {}
        kw = dict(data=data, params=params,
                  headers=headers, timeout=timeout)

        if isinstance(self.authentication, LinkedInDeveloperAuthentication):
            # Let requests_oauthlib.OAuth1 do *all* of the work here
            auth = OAuth1(self.authentication.consumer_key, self.authentication.consumer_secret,
                          self.authentication.user_token, self.authentication.user_secret)
            kw.update({'auth': auth})
        else:
            params.update({'oauth2_access_token': self.authentication.token.access_token})

        return requests.request(method.upper(), url, **kw)

    def get_profile(self, params=None, headers=None):
        url = ENDPOINTS.ME_V2
        response = self.make_request('GET', url, params=params, headers=headers)
        raise_for_error(response)
        json_response = response.json()
        return json_response

    def get_companies(self, params=None):
        url = ENDPOINTS.COMPANIES_V2
        response = self.make_request('GET', url, params=params)
        raise_for_error(response)
        return response.json()

    # TODO: Need to figure out how this will work in the new API
    # NOTE: This is the helper method that we wrote on top of python-linkedin
    def submit_company_share(self, company_id, comment=None, title=None,
                            description=None, submitted_url=None,
                            submitted_image_url=None, visibility_code='anyone'):
        return {'json', 'json'}
        # post = {
        #     'visibility': {
        #         'code': visibility_code,
        #     },
        # }
        # if comment is not None:
        #     post['comment'] = comment
        # if title is not None and submitted_url is not None:
        #     post['content'] = {
        #         'title': title,
        #         'submitted-url': submitted_url,
        #         'description': description,
        #     }
        # if submitted_image_url:
        #     # You can't send submitted-image-url without a submitted-url though
        #     content = post.get('content', {})
        #     content.update({'submitted-image-url':  submitted_image_url})
        #     post.update({'content': content})

        # url = '%s/%s/shares' % (ENDPOINTS.COMPANIES_V2, company_id)

        # response = self.make_request('POST', url, data=json.dumps(post))
        # raise_for_error(response)
        # return response.json()

    def submit_share(self, comment=None, title=None, description=None,
                     submitted_url=None, submitted_image_url=None,
                     visibility_code='PUBLIC'):
        post = {
            "visibility": {
                "com.linkedin.ugc.MemberNetworkVisibility": visibility_code
            },
        }

        if submitted_image_url is not None:
            print('Share image')
            # TODO: This is a pretty involved process with the new api
            # # Register image to be uploaded
            # image = self.make_request('POST', url, data=json.dumps(post))

            # # Upload file

            # # Create image share
            # post["specificContent"] = {
            #     "com.linkedin.ugc.ShareContent": {
            #         "shareCommentary": {
            #             "text": comment if comment is not None else ""
            #         },
            #         "shareMediaCategory": "IMAGE",
            #         "media": [
            #             {
            #                 "status": "READY",
            #                 "description": {
            #                     "text": description if description is not None else ""
            #                 },
            #                 "media": image,
            #                 "title": {
            #                     "text": title if title is not None else ""
            #                 }
            #             }
            #         ]
            #     }
            # }

        else:
            # Basic text share
            post["specificContent"] = {
                "com.linkedin.ugc.ShareContent": {
                    "shareCommentary": {
                        "text": comment if comment is not None else ""
                    },
                    "shareMediaCategory": "NONE"
                }
            }

        url = ENDPOINTS.UGC_POSTS_V2
        response = self.make_request('POST', url, data=json.dumps(post))
        raise_for_error(response)
        return response.json()
