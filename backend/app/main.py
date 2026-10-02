from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.auth import router as auth_router
from app.database import Base, engine

from app.routes.upload import router as upload_router
from app.routes.incidents import router as incidents_router
from app.routes.dashboard import router as dashboard_router
from app.routes.ai_analyst import router as ai_analyst_router


Base.metadata.create_all(
    bind=engine
)


app = FastAPI(
    title="SOCVision",
    version="1.0"
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://localhost:5174",
        "http://localhost:8080"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


app.include_router(
    upload_router
)

app.include_router(
    incidents_router
)

app.include_router(
    dashboard_router
)

app.include_router(
    auth_router
)

app.include_router(
    ai_analyst_router
)


@app.get("/")
def root():
    return {
        "application": "SOCVision",
        "status": "Running",
        "version": "1.0"
    }