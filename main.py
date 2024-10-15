from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from typing import List
import requests
from requests import Response
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# OAuth2 scheme
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI()

# CORS settings
origins = [
    "http://localhost:8100",  # Your frontend URL
    # Add other origins if needed
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],  # Allow all HTTP methods
    allow_headers=["*"],  # Allow all headers
)

# Set your realm name here
REALM = "my-realm-2"
JWKS_URL = f"http://keycloak:8080/realms/{REALM}/protocol/openid-connect/certs"

def log_request_and_response(response: Response):
    """Logs the outgoing request and the response."""
    request = response.request
    logger.info(f"Outgoing Request: {request.method} {request.url}")
    logger.info(f"Request Headers: {request.headers}")
    if request.body:
        logger.info(f"Request Body: {request.body}")

    logger.info(f"Response Status: {response.status_code}")
    logger.info(f"Response Headers: {response.headers}")
    logger.info(f"Response Body: {response.text}")

def get_public_key():
    try:
        # Send request to fetch JWKS
        response = requests.get(JWKS_URL)
        log_request_and_response(response)  # Log the request and response
        response.raise_for_status()  # Ensure we raise an error for bad responses
        jwks = response.json()

        if not jwks.get('keys'):
            raise ValueError("No keys found in JWKS")

        # Get the first key's X.509 certificate
        public_key = jwks['keys'][0]['x5c'][0]

        # Create PEM format
        pem_key = f"-----BEGIN CERTIFICATE-----\n{public_key}\n-----END CERTIFICATE-----"

        # Load the public key from the certificate
        cert = x509.load_pem_x509_certificate(pem_key.encode(), default_backend())
        return cert.public_key()  # Returns the public key object
    except requests.exceptions.HTTPError as e:
        logger.error(f"Failed to fetch JWKS: {e}, URL: {JWKS_URL}")
        raise
    except Exception as e:
        logger.error(f"Error in getting public key: {e}")
        raise

def verify_token(token: str, required_scopes: List[str]):
    try:
        public_key = get_public_key()

        # Decode the JWT using the public key
        logger.info(f"Starting token decode")
        payload = jwt.decode(token, public_key, algorithms=["RS256"], audience="my-app")
        logger.info(f"Payload: {payload}")
        scopes = payload.get("scope", "").split(" ")

        # Check if the required scopes are in the token
        if not all(scope in scopes for scope in required_scopes):
            raise HTTPException(status_code=403, detail="Not enough permissions")
        return payload
    except JWTError as e:
        logger.error(f"JWT error: {e}, Token: {token}")
        raise HTTPException(status_code=403, detail=f"Could not validate credentials: {str(e)}")

@app.get("/read")
async def read_data(token: str = Depends(oauth2_scheme)):
    verify_token(token, ["read-access"])  # Validate token for read access
    return {"message": "You have read access"}

@app.post("/write")
async def write_data(token: str = Depends(oauth2_scheme)):
    verify_token(token, ["write-access"])  # Validate token for write access
    return {"message": "You have write access"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)