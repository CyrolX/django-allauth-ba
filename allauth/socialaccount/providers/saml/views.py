import binascii
# See l.30-32
#import logging

from django.http import HttpRequest, HttpResponse, HttpResponseRedirect, JsonResponse
from django.urls import reverse
from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.csrf import csrf_exempt

from onelogin.saml2.auth import OneLogin_Saml2_Settings
from onelogin.saml2.errors import OneLogin_Saml2_Error

from allauth.account.adapter import get_adapter as get_account_adapter
from allauth.account.internal.decorators import login_not_required
from allauth.core.internal import httpkit
from allauth.socialaccount.helpers import (
    complete_social_login,
    render_authentication_error,
)
from allauth.socialaccount.providers.base.constants import AuthError, AuthProcess
from allauth.socialaccount.providers.base.views import BaseLoginView
from allauth.socialaccount.sessions import LoginSession

from .utils import build_auth, build_saml_config, decode_relay_state, get_app_or_404

# BA Imports
import time
from allauth.allauth_loggers import saml_logger

# Original:
# logger = logging.getLogger(__name__)
# We comment the logger out so it doesn't interfere with our logging endeavours.


class SAMLViewMixin:
    def get_app(self, organization_slug):
        app = get_app_or_404(self.request, organization_slug)
        return app

    def get_provider(self, organization_slug):
        app = self.get_app(organization_slug)
        return app.get_provider(self.request)

# BA: As the Assertion Consumer Service is a vital part of a SAML ecosystem, this view
# should be measured.
@method_decorator(csrf_exempt, name="dispatch")
@method_decorator(login_not_required, name="dispatch")
class ACSView(SAMLViewMixin, View):
    def dispatch(self, request, organization_slug):
        saml_logger.debug("The ACSView's dispatch method has been called.")
        saml_logger.warning(f"'request' @ allauth.socialaccount.providers.saml.views.ACSView is {request}")
        beginning_time = time.process_time()
        url = reverse(
            "saml_finish_acs",
            kwargs={"organization_slug": organization_slug},
        )
        response = HttpResponseRedirect(url)
        acs_session = LoginSession(request, "saml_acs_session", "saml-acs-session")
        acs_session.store.update({"request": httpkit.serialize_request(request)})
        acs_session.save(response)
        end_time = time.process_time()
        saml_logger.info(f"'dispatch' @ allauth.socialaccount.providers.saml.views.ACSView called w/ eval time {end_time - beginning_time}")
        return response


acs = ACSView.as_view()

# BA: As the Assertion Consumer Service is a vital part of a SAML ecosystem, this view
# should be measured.
@method_decorator(login_not_required, name="dispatch")
class FinishACSView(SAMLViewMixin, View):
    def dispatch(self, request, organization_slug):
        saml_logger.debug("The FinishACSView's dispatch method has been called.")
        beginning_time = time.process_time()
        provider = self.get_provider(organization_slug)
        acs_session = LoginSession(request, "saml_acs_session", "saml-acs-session")
        acs_request = None
        acs_request_data = acs_session.store.get("request")
        if acs_request_data:
            acs_request = httpkit.deserialize_request(acs_request_data, HttpRequest())
        acs_session.delete()
        if not acs_request:
            # See l.30-32
            #logger.error("Unable to finish login, SAML ACS session missing")
            # Original:
            #return render_authentication_error(request, provider)
            auth_error = render_authentication_error(request, provider)
            end_time = time.process_time()
            saml_logger.info(f"'dispatch' @ allauth.socialaccount.providers.saml.views.FinishACSView called w/ eval time {end_time - beginning_time}")
            saml_logger.debug("'dispatch' failed: No ACS Session.")
            return auth_error

        auth = build_auth(acs_request, provider)
        saml_logger.warning(f"'auth.__nameid' @ allauth.socialaccount.providers.saml.views.FinishACSView is {auth.get_nameid()}")
        error_reason = None
        errors = []
        try:
            # We're doing the check for a valid `InResponeTo` ourselves later on
            # (*) by checking if there is a matching state stashed.
            auth.process_response(request_id=None)
        except binascii.Error:
            errors = ["invalid_response"]
            error_reason = "Invalid response"
        except OneLogin_Saml2_Error as e:
            errors = ["error"]
            error_reason = str(e)
        if not errors:
            errors = auth.get_errors()
        if errors:
            # e.g. ['invalid_response']
            error_reason = auth.get_last_error_reason() or error_reason
            # See l.30-32
            #logger.error(
            #    "Error processing SAML ACS response: %s: %s"
            #    % (", ".join(errors), error_reason)
            #)
            # Original:
            #return render_authentication_error(
            #    request,
            #    provider,
            #    extra_context={
            #        "saml_errors": errors,
            #        "saml_last_error_reason": error_reason,
            #    },
            #)
            auth_error = render_authentication_error(
                request,
                provider,
                extra_context={
                    "saml_errors": errors,
                    "saml_last_error_reason": error_reason,
                },
            )
            end_time = time.process_time()
            saml_logger.info(f"'dispatch' @ allauth.socialaccount.providers.saml.views.FinishACSView called w/ eval time {end_time - beginning_time}")
            saml_logger.debug("'dispatch' failed: ACS Response processing failed.")
            return auth_error
        if not auth.is_authenticated():
            # Original:
            #return render_authentication_error(
            #    request, provider, error=AuthError.CANCELLED
            #)
            auth_error = render_authentication_error(
                request, provider, error=AuthError.CANCELLED
            )
            end_time = time.process_time()
            saml_logger.info(f"'dispatch' @ allauth.socialaccount.providers.saml.views.FinishACSView called w/ eval time {end_time - beginning_time}")
            saml_logger.debug("'dispatch' failed: User is not authenticated.")
        login = provider.sociallogin_from_response(request, auth)
        # (*) If we (the SP) initiated the login, there should be a matching
        # state.
        state_id = auth.get_last_response_in_response_to()
        if state_id:
            login.state = provider.unstash_redirect_state(request, state_id)
        else:
            # IdP initiated SSO
            reject = provider.app.settings.get("advanced", {}).get(
                "reject_idp_initiated_sso", True
            )
            if reject:
                # See l.30-32
                #logger.error("IdP initiated SSO rejected")
                # Original:
                #return render_authentication_error(request, provider)
                auth_error = render_authentication_error(request, provider)
                end_time = time.process_time()
                saml_logger.info(f"'dispatch' @ allauth.socialaccount.providers.saml.views.FinishACSView called w/ eval time {end_time - beginning_time}")
                saml_logger.debug("'dispatch' failed: IdP-initiated SSO is not allowed.")
                return auth_error
            next_url = decode_relay_state(acs_request.POST.get("RelayState"))
            login.state["process"] = AuthProcess.LOGIN
            if next_url:
                login.state["next"] = next_url
        sociallogin_return = complete_social_login(request, login)
        end_time = time.process_time()
        saml_logger.info(f"<{login.state['data']['eval_user']}> 'dispatch' @ allauth.socialaccount.providers.saml.views.FinishACSView called w/ eval time {end_time - beginning_time}")
        saml_logger.debug("Execution of 'dispatch' was successful.")
        # Original:
        #return complete_social_login(request, login)
        return sociallogin_return


finish_acs = FinishACSView.as_view()


@method_decorator(csrf_exempt, name="dispatch")
@method_decorator(login_not_required, name="dispatch")
class SLSView(SAMLViewMixin, View):
    def dispatch(self, request, organization_slug):
        provider = self.get_provider(organization_slug)
        auth = build_auth(self.request, provider)
        should_logout = request.user.is_authenticated
        account_adapter = get_account_adapter(request)

        def force_logout():
            account_adapter.logout(request)

        redirect_to = None
        error_reason = None
        try:
            redirect_to = auth.process_slo(
                delete_session_cb=force_logout, keep_local_session=not should_logout
            )
        except OneLogin_Saml2_Error as e:
            error_reason = str(e)
        errors = auth.get_errors()
        if errors:
            error_reason = auth.get_last_error_reason() or error_reason
            # See l.30-32
            #logger.error(
            #    "Error processing SAML SLS response: %s: %s"
            #    % (", ".join(errors), error_reason)
            #)
            resp = HttpResponse(error_reason, content_type="text/plain")
            resp.status_code = 400
            return resp
        if not redirect_to:
            redirect_to = account_adapter.get_logout_redirect_url(request)
        return HttpResponseRedirect(redirect_to)


sls = SLSView.as_view()


@method_decorator(login_not_required, name="dispatch")
class MetadataView(SAMLViewMixin, View):
    def dispatch(self, request, organization_slug):
        provider = self.get_provider(organization_slug)
        config = build_saml_config(
            self.request, provider.app.settings, organization_slug
        )
        saml_settings = OneLogin_Saml2_Settings(
            settings=config, sp_validation_only=True
        )
        metadata = saml_settings.get_sp_metadata()
        errors = saml_settings.validate_metadata(metadata)

        if len(errors) > 0:
            resp = JsonResponse({"errors": errors})
            resp.status_code = 500
            return resp

        return HttpResponse(content=metadata, content_type="text/xml")


metadata = MetadataView.as_view()


@method_decorator(login_not_required, name="dispatch")
class LoginView(SAMLViewMixin, BaseLoginView):
    def get_provider(self):
        app = self.get_app(self.kwargs["organization_slug"])
        return app.get_provider(self.request)


login = LoginView.as_view()
