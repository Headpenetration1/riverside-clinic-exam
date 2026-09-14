from flask import Flask


def register_blueprints(app: Flask) -> None:
    from . import account, admin, auth, chat, documents, messages, pages, password_reset, patients

    app.register_blueprint(auth.bp)
    app.register_blueprint(account.me_bp)
    app.register_blueprint(password_reset.bp)
    app.register_blueprint(documents.bp)
    app.register_blueprint(messages.bp)
    app.register_blueprint(patients.bp)
    app.register_blueprint(admin.bp)
    app.register_blueprint(chat.bp)
    app.register_blueprint(pages.bp)
