from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from typing import List
import requests

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
REALM = "my-realm"
JWKS_URL = f"http://keycloak:8080/realms/{REALM}/protocol/openid-connect/certs"


def get_public_key():
    try:
        response = requests.get(JWKS_URL)
        response.raise_for_status()  # Raise an error for bad responses
        jwks = response.json()

        # Ensure keys are available
        if not jwks.get('keys'):
            raise ValueError("No keys found in JWKS")

        # Assuming you want the first key in the JWKS
        public_key = jwks['keys'][0]['x5c'][0]

        # Format it as a PEM key
        pem_key = f"-----BEGIN CERTIFICATE-----\n{public_key}\n-----END CERTIFICATE-----"
        return pem_key
    except requests.exceptions.HTTPError as e:
        print(f"Failed to fetch JWKS: {e}, URL: {JWKS_URL}")
        raise
    except Exception as e:
        print(f"Error in getting public key: {e}")
        raise

def verify_token(token: str, required_scopes: List[str]):
    try:
        public_key = get_public_key()
        # Decode the JWT using the public key
        payload = jwt.decode(token, public_key, algorithms=["RS256"])
        scopes = payload.get("scope", "").split(" ")

        # Check if the required scopes are in the token
        if not all(scope in scopes for scope in required_scopes):
            raise HTTPException(status_code=403, detail="Not enough permissions")
        return payload
    except JWTError as e:
        print(f"jwt error: {e}, {token}")
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