from django.http import HttpResponseRedirect
from django.urls import reverse
from django.utils.http import urlencode

from allauth.socialaccount.providers.base import Provider, ProviderAccount

# BA Imports
import time
from allauth.allauth_loggers import saml_logger


class SAMLAccount(ProviderAccount):
    pass


class SAMLProvider(Provider):
    saml_logger.debug("My SAMLProvider has been instantiated.")
    id = "saml"
    name = "SAML"
    supports_redirect = True
    account_class = SAMLAccount
    default_attribute_mapping = {
        "uid": [
            "urn:oasis:names:tc:SAML:attribute:subject-id",
        ],
        "email": [
            "urn:oid:0.9.2342.19200300.100.1.3",
            "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
        ],
        "email_verified": [
            "http://schemas.auth0.com/email_verified",
        ],
        "first_name": [
            "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname",
            "urn:oid:2.5.4.42",
        ],
        "last_name": [
            "urn:oid:2.5.4.4",
        ],
        "username": [
            "http://schemas.auth0.com/nickname",
        ],
    }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = self.app.name or self.app.client_id or self.name

    def get_login_url(self, request, **kwargs):
        url = reverse("saml_login", kwargs={"organization_slug": self.app.client_id})
        if kwargs:
            url = url + "?" + urlencode(kwargs)
        return url

    def extract_extra_data(self, data):
        return data.get_attributes()

    def extract_uid(self, data):
        """http://docs.oasis-open.org/security/saml-subject-id-attr/v1.0/csprd01/saml-subject-id-attr-v1.0-csprd01.html

        Quotes:

        "While the Attributes defined in this profile have as a goal the
        explicit replacement of the <saml:NameID> element as a means of subject
        identification, it is certainly possible to compose them with existing
        NameID usage provided the same subject is being identified. This can
        also serve as a migration strategy for existing applications."


        "SAML does not define an identifier that meets all of these
        requirements well. It does standardize a kind of NameID termed
        “persistent” that meets some of them in the particular case of so-called
        “pairwise” identification, where an identifier varies by relying
        party. It has seen minimal adoption outside of a few contexts, and fails
        at the “compact” and “simple to handle” criteria above, on top of the
        disadvantages inherent with all NameID usage."

        Overall, our strategy is to prefer a uid resulting from explicit
        attribute mappings, and only if there is no such uid fallback to the
        NameID.
        """
        uid = self._extract(data).get("uid")
        if uid is None:
            uid = data.get_nameid()
        return uid

    def extract_common_fields(self, data):
        ret = self._extract(data)
        ret.pop("uid", None)
        return ret

    def _extract(self, data):
        provider_config = self.app.settings
        raw_attributes = data.get_attributes()
        attributes = {}
        attribute_mapping = provider_config.get(
            "attribute_mapping", self.default_attribute_mapping
        )
        # map configured provider attributes
        for key, provider_keys in attribute_mapping.items():
            if isinstance(provider_keys, str):
                provider_keys = [provider_keys]
            for provider_key in provider_keys:
                attribute_list = raw_attributes.get(provider_key, None)
                if attribute_list is not None and len(attribute_list) > 0:
                    attributes[key] = attribute_list[0]
                    break
        email_verified = attributes.get("email_verified")
        if email_verified:
            email_verified = email_verified.lower() in ["true", "1", "t", "y", "yes"]
            attributes["email_verified"] = email_verified

        # If we did not find an email, check if the NameID contains the email.
        if not attributes.get("email") and (
            data.get_nameid_format()
            == "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
            # Alternatively, if `use_id_for_email` is true, then we always interpret the nameID as email
            or provider_config.get("use_nameid_for_email", False)
        ):
            attributes["email"] = data.get_nameid()

        return attributes

    # BA: This should be measured.
    def redirect(self, request, process, next_url=None, data=None, **kwargs):
        from allauth.socialaccount.providers.saml.utils import build_auth

        beginning_time = time.process_time()
        saml_logger.warning(f"'request' @ allauth.socialaccount.providers.saml.provider is {request}")
        saml_logger.warning(f"'request.path' @ allauth.socialaccount.providers.saml.provider is {request.path}")
        saml_logger.warning(f"'request.path_info' @ allauth.socialaccount.providers.saml.provider is {request.path_info}")
        auth = build_auth(request, self)
        build_auth_end_time = time.process_time()
        # If we pass `return_to=None` `auth.login` will use the URL of the
        # current view.
        redirect = auth.login(return_to="")
        auth_login_end_time = time.process_time()
        self.stash_redirect_state(
            request,
            process,
            next_url,
            data,
            state_id=auth.get_last_request_id(),
            **kwargs,
        )
        end_time = time.process_time()
        saml_logger.info(f"'redirect' @ allauth.socialaccount.providers.saml.provider called w/ eval time {end_time - beginning_time}")
        # These logs are written after the redirect, so that the redirect can
        # still be used to initialize a new user in the json file that is created
        # based on the log file.
        saml_logger.info(f"'build_auth' @ allauth.socialaccount.providers.saml.provider called w/ eval time {build_auth_end_time - beginning_time}")
        saml_logger.info(f"'login' @ allauth.socialaccount.providers.saml.provider called w/ eval time {auth_login_end_time - build_auth_end_time}")

        return HttpResponseRedirect(redirect)


provider_classes = [SAMLProvider]
