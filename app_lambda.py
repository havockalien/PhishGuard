"""AWS Lambda entry point for the FastAPI app."""

from mangum import Mangum

from inference_api import app

handler = Mangum(app)
