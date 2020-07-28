"""HTTP Handlers for the hub server"""
# Copyright (c) Jupyter Development Team.
# Distributed under the terms of the Modified BSD License.
import asyncio
import os
import requests
import uuid
import json

from contextlib import closing

from tornado import web
from tornado.escape import url_escape
from tornado.httputil import url_concat

from ..utils import maybe_future
from ..orm import Spawner
from .base import BaseHandler


class LogoutHandler(BaseHandler):
    """Log a user out by clearing their login cookie."""

    @property
    def shutdown_on_logout(self):
        return self.settings.get('shutdown_on_logout', False)

    async def _shutdown_servers(self, user):
        """Shutdown servers for logout

        Get all active servers for the provided user, stop them.
        ""
        active_servers = [
            name
            for (name, spawner) in user.spawners.items()
            if spawner.active and not spawner.pending
        ]
        if active_servers:
            self.log.info("Shutting down %s's servers", user.name)
            futures = []
            for server_name in active_servers:
                futures.append(maybe_future(self.stop_single_user(user, server_name)))
            await asyncio.gather(*futures)
        """
        # Use Jupyter-jsc code to stop servers and revoke the token. So you will be logged out from Unity, too
        if user:
            uuidcode = uuid.uuid4().hex
            self.log.info("username={}, uuidcode={}, action=logout".format(user.name, uuidcode))
            state = await user.get_auth_state()
            if state:
                with open(user.authenticator.orchestrator_token_path, 'r') as f:
                    intern_token = f.read().rstrip()
                json_dic = {'accesstoken': state['accesstoken'],
                        'refreshtoken': state['refreshtoken']}
                header = {'Intern-Authorization': intern_token,
                          'uuidcode': uuidcode,
                          'stopall': 'true',
                          'username': user.name,
                          'escapedusername': user.escaped_name,
                          'expire': state['expire']}
                if state['login_handler'] == 'jscusername':
                    header['tokenurl'] = os.environ.get('JSCUSERNAME_TOKEN_URL', 'https://unity-jsc.fz-juelich.de/jupyter-oauth2/token')
                    header['authorizeurl'] = os.environ.get('JSCUSERNAME_AUTHORIZE_URL', 'https://unity-jsc.fz-juelich.de/jupyter-oauth2-as-username/oauth2-authz')
                elif state['login_handler'] == 'jscldap':
                    header['tokenurl'] = os.environ.get('JSCLDAP_TOKEN_URL', 'https://unity-jsc.fz-juelich.de/jupyter-oauth2/token')
                    header['authorizeurl'] = os.environ.get('JSCLDAP_AUTHORIZE_URL', 'https://unity-jsc.fz-juelich.de/jupyter-oauth2-as/oauth2-authz')
                elif state['login_handler'] == 'hdfaai':
                    header['tokenurl'] = os.environ.get('HDFAAI_TOKEN_URL', 'https://unity.helmholtz-data-federation.de/oauth2/token')
                    header['authorizeurl'] = os.environ.get('HDFAAI_AUTHORIZE_URL', 'https://unity.helmholtz-data-federation.de/oauth2-as/oauth2-authz')
                else:
                    self.log.info("Use default tokenurl")
                    header['tokenurl'] = os.environ.get('JSCLDAP_TOKEN_URL', 'https://unity-jsc.fz-juelich.de/jupyter-oauth2/token')
                    header['authorizeurl'] = os.environ.get('JSCLDAP_AUTHORIZE_URL', 'https://unity-jsc.fz-juelich.de/jupyter-oauth2-as/oauth2-authz')
                self.log.debug("uuidcode={} - User Spawners: {}".format(uuidcode, user.spawners))
                names = []
                db_spawner_list = user.db.query(Spawner).filter(Spawner.user_id == user.orm_user.id).all()
                for db_spawner in db_spawner_list:
                    names.append(db_spawner.name)
                for name in names:
                    self.log.debug("uuidcode={} - 'Stop' {}".format(uuidcode, name))
                    await user.spawners[name].cancel(uuidcode, True)
                self.log.debug("{} - Revoke access and refresh token - uuidcode={}".format(user.name, uuidcode))
                try:
                    with open(user.authenticator.j4j_urls_paths, 'r') as f:
                        urls = json.load(f)
                    url = urls.get('orchestrator', {}).get('url_revoke', '<no_url_found>')
                    with closing(requests.post(url,
                                               headers=header,
                                               json=json_dic,
                                               verify=False)) as r:
                        if r.status_code != 202:
                            self.log.warning("Failed J4J_Orchestrator communication: {} {}".format(r.text, r.status_code))
                except:
                    self.log.exception("{} - Could not revoke token".format(user.name))
                state['accesstoken'] = ''
                state['refreshtoken'] = ''
                state['expire'] = ''
                state['oauth_user'] = ''
                state['scope'] = []
                state['login_handler'] = ''
                await user.save_auth_state(state)


    def _backend_logout_cleanup(self, name):
        """Default backend logout actions

        Send a log message, clear some cookies, increment the logout counter.
        """
        self.log.info("User logged out: %s", name)
        self.clear_login_cookie()
        self.statsd.incr('logout')

    async def default_handle_logout(self, shutdown=True):
        """The default logout action

        Optionally cleans up servers, clears cookies, increments logout counter
        Cleaning up servers can be prevented by setting shutdown_on_logout to
        False.
        """
        user = self.current_user
        if user:
            if self.shutdown_on_logout and shutdown:
                await self._shutdown_servers(user)

            self._backend_logout_cleanup(user.name)

    async def handle_logout(self):
        """Custom user action during logout

        By default a no-op, this function should be overridden in subclasses
        to have JupyterHub take a custom action on logout.
        """
        return

    async def render_logout_page(self):
        """Render the logout page, if any

        Override this function to set a custom logout page.
        """
        if self.authenticator.auto_login:
            html = self.render_template('logout.html')
            self.finish(html)
        else:
            self.redirect(self.settings['login_url'], permanent=False)

    async def get(self):
        """Log the user out, call the custom action, forward the user
            to the logout page
        """
        stopall = self.get_argument("stopall", "true", True)
        self.log.debug("Logout StopAll: {}".format(stopall))
        await self.default_handle_logout(stopall.lower() == "true")
        await self.handle_logout()
        await self.render_logout_page()


class LoginHandler(BaseHandler):
    """Render the login page."""

    def _render(self, login_error=None, username=None):
        return self.render_template(
            'login.html',
            next=url_escape(self.get_argument('next', default='')),
            username=username,
            login_error=login_error,
            custom_html=self.authenticator.custom_html,
            login_url=self.settings['login_url'],
            authenticator_login_url=url_concat(
                self.authenticator.login_url(self.hub.base_url),
                {'next': self.get_argument('next', '')},
            ),
        )

    async def get(self):
        self.statsd.incr('login.request')
        user = self.current_user
        if user:
            # set new login cookie
            # because single-user cookie may have been cleared or incorrect
            self.set_login_cookie(user)
            self.redirect(self.get_next_url(user), permanent=False)
        else:
            if self.authenticator.auto_login:
                auto_login_url = self.authenticator.login_url(self.hub.base_url)
                if auto_login_url == self.settings['login_url']:
                    # auto_login without a custom login handler
                    # means that auth info is already in the request
                    # (e.g. REMOTE_USER header)
                    user = await self.login_user()
                    if user is None:
                        # auto_login failed, just 403
                        raise web.HTTPError(403)
                    else:
                        self.redirect(self.get_next_url(user))
                else:
                    if self.get_argument('next', default=False):
                        auto_login_url = url_concat(
                            auto_login_url, {'next': self.get_next_url()}
                        )
                    self.redirect(auto_login_url)
                return
            username = self.get_argument('username', default='')
            self.finish(self._render(username=username))

    async def post(self):
        # parse the arguments dict
        data = {}
        for arg in self.request.arguments:
            data[arg] = self.get_argument(arg, strip=False)

        auth_timer = self.statsd.timer('login.authenticate').start()
        user = await self.login_user(data)
        auth_timer.stop(send=False)

        if user:
            # register current user for subsequent requests to user (e.g. logging the request)
            self._jupyterhub_user = user
            self.redirect(self.get_next_url(user))
        else:
            html = self._render(
                login_error='Invalid username or password', username=data['username']
            )
            self.finish(html)


# /login renders the login page or the "Login with..." link,
# so it should always be registered.
# /logout clears cookies.
default_handlers = [(r"/login", LoginHandler), (r"/logout", LogoutHandler)]
