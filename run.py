"""Entry point: `flask --app run run --debug` for development, or a WSGI server in production."""
from app import create_app

app = create_app()

if __name__ == "__main__":  # pragma: no cover
    app.run(host="127.0.0.1", port=5000)
