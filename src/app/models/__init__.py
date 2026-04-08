"""Import all models so Alembic autogenerate discovers them."""

import src.app.models.oauth_account
import src.app.models.role
import src.app.models.session
import src.app.models.subscription
import src.app.models.totp_secret
import src.app.models.user
import src.app.models.verification_token  # noqa: F401
