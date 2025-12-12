import base64
import hashlib
from secrets import token_urlsafe

# BA Imports
import time
from allauth.allauth_loggers import oidc_logger

def generate_code_challenge(tu = None):
    # Create a code verifier with a length of 128 characters
    beginning_time = time.process_time()
    code_verifier = token_urlsafe(96)
    hashed_verifier = hashlib.sha256(code_verifier.encode("ascii"))
    code_challenge = base64.urlsafe_b64encode(hashed_verifier.digest())
    code_challenge_without_padding = code_challenge.rstrip(b"=")
    # Original
    #return {
    #    "code_verifier": code_verifier,
    #    "code_challenge_method": "S256",
    #    "code_challenge": code_challenge_without_padding,
    #}
    return_value = {
        "code_verifier": code_verifier,
        "code_challenge_method": "S256",
        "code_challenge": code_challenge_without_padding,
    }
    end_time = time.process_time()
    oidc_logger.info(f"<{tu}> 'generate_code_challenge' @ allauth.socialaccount.providers.oauth2.utils called w/ eval time {end_time - beginning_time}")
    return return_value
