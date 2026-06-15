"""Profile / preferences schemas — US #165.

The user-service stores arbitrary UI/UX preferences in a JSONB column. A small
set of well-known keys (``theme``, ``language``) is type-checked; any other key
is accepted and round-tripped untouched so new client preferences need no schema
or migration change. A byte cap bounds JSONB growth (a user-writable column is
otherwise an unbounded-storage surface).
"""

import json
import uuid
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

# Upper bound on the JSON-serialized preferences blob. Generous for real UI
# settings while denying a user from stuffing the column with arbitrary payload.
MAX_PREFERENCES_BYTES = 8192


class ProfilePreferences(BaseModel):
    """A user's preferences. Known keys are validated; extra keys pass through.

    ``extra="allow"`` keeps unrecognized keys, so the model both validates the
    well-known prefs and serves as a transparent container for client-defined
    ones.
    """

    model_config = ConfigDict(extra="allow")

    theme: Literal["light", "dark", "system"] | None = None
    language: str | None = Field(default=None, max_length=35)

    @model_validator(mode="after")
    def _enforce_size_limit(self) -> "ProfilePreferences":
        encoded = json.dumps(self.model_dump(exclude_none=True)).encode("utf-8")
        if len(encoded) > MAX_PREFERENCES_BYTES:
            msg = f"preferences exceed the {MAX_PREFERENCES_BYTES}-byte limit"
            raise ValueError(msg)
        return self

    def to_storage(self) -> dict[str, Any]:
        """Plain dict to persist — drops keys whose value is ``None``."""
        return self.model_dump(exclude_none=True)


class ProfileRead(BaseModel):
    """The authenticated user's profile preferences."""

    model_config = ConfigDict(frozen=True)

    user_id: uuid.UUID
    preferences: dict[str, Any]


class ProfileUpdate(BaseModel):
    """Replace the authenticated user's preferences (PUT semantics).

    The submitted ``preferences`` object replaces the stored one wholesale — a
    settings page reads the full object and writes it back, so partial-merge
    surprises are avoided.
    """

    model_config = ConfigDict(frozen=True)

    preferences: ProfilePreferences
