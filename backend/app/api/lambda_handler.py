"""AWS Lambda adapter for the unchanged FastAPI/DRISHTI application."""

from mangum import Mangum

from app.api.main import app

handler = Mangum(app, lifespan="off")
