from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
from fastapi.middleware.cors import CORSMiddleware
from jose import JWTError, jwt
from typing import List

# Constants
SECRET_KEY = "your_secret_key"  # Replace with your actual secret key
ALGORITHM = "HS256"  # The algorithm used for signing the JWT

# OAuth2 scheme
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI()

# CORS middleware setup
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows all origins, adjust as needed for production
    allow_credentials=True,
    allow_methods=["*"],  # Allows all methods (GET, POST, etc.)
    allow_headers=["*"],  # Allows all headers
)

def verify_token(token: str, required_scopes: List[str]):
    try:
        # Decode the JWT
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        scopes = payload.get("scope", "").split(" ")
        print(f"verify_token: {scopes}, required_scopes: {required_scopes}")
        # Check if the required scopes are in the token
        if not all(scope in scopes for scope in required_scopes):
            raise HTTPException(status_code=403, detail="Not enough permissions")
        return payload
    except JWTError:
        raise HTTPException(status_code=403, detail="Could not validate credentials")

@app.get("/read")
async def read_data(token: str = Depends(oauth2_scheme)):
    print(f"/read {token}")
    verify_token(token, ["read-access"])  # Validate token for read access
    return {"message": "You have read access"}

@app.post("/write")
async def write_data(token: str = Depends(oauth2_scheme)):
    verify_token(token, ["write-access"])  # Validate token for write access
    return {"message": "You have write access"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)