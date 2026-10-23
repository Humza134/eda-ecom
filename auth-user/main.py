from fastapi import FastAPI
from typing import Any
from database.db_config import config
from router.user_routes import auth_router
from redis_client import redis_lifespan
from jwcrypto import jwk
from utils import PUBLIC_KEY


key = jwk.JWK.from_pem(PUBLIC_KEY.encode("utf-8"))

jwk_dict = key.export_public(as_dict=True)
jwk_dict["kid"] = config.JWT_KEY_ID
jwk_dict["use"] = "sig"
jwk_dict["alg"] = config.ALGORITHM
jwks = {"keys": [jwk_dict]}

app = FastAPI(
    title="Auth User API",
    version="1.0.0",
    lifespan=redis_lifespan,
)

app.include_router(auth_router, prefix="/auth", tags=["auth"])

@app.get("/")
async def root():
    return {"message": "Hello World"}

@app.get("/.well-known/jwks.json")
def jwks_endpoint()-> dict[str, Any]:
    return jwks
