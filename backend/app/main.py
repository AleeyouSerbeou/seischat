"""FastAPI application entry point."""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.exceptions import RequestValidationError
from fastapi import HTTPException

from app.api.errors import http_exception_handler, validation_exception_handler
from app.api.routes.auth import router as auth_router
from app.api.routes.health import router as health_router
from app.api.routes.messages import router as messages_router
from app.api.routes.users import router as users_router
from app.core.config import get_settings
from app.websocket import chat_socket

settings = get_settings()
app = FastAPI(title="SeisChat API")
app.add_exception_handler(RequestValidationError, validation_exception_handler)
app.add_exception_handler(HTTPException, http_exception_handler)

cors_origins = set()
for candidate in [
    settings.frontend_origin,
    "https://seischat-web.onrender.com",
    "http://localhost:5173",
    "http://127.0.0.1:5173",
]:
    if candidate:
        clean = candidate.rstrip("/")
        cors_origins.add(clean)
        cors_origins.add(f"{clean}/")

app.add_middleware(
    CORSMiddleware,
    allow_origins=list(cors_origins),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.include_router(health_router)
app.include_router(auth_router)
app.include_router(messages_router)
app.include_router(users_router)
app.add_api_websocket_route("/ws/chat", chat_socket)

if __name__ == "__main__":
    import os
    import uvicorn

    port = int(os.environ.get("PORT", settings.port))
    uvicorn.run("app.main:app", host="0.0.0.0", port=port)

