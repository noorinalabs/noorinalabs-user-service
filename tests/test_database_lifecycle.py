import pytest

from src.app import database
from src.app.config import Settings


@pytest.mark.asyncio
async def test_close_db_disposes_engine(monkeypatch: pytest.MonkeyPatch) -> None:
    test_settings = Settings(DATABASE_URL="sqlite+aiosqlite:///:memory:")  # type: ignore[call-arg]
    monkeypatch.setattr(database, "get_settings", lambda: test_settings)

    await database.init_db()
    engine = database._engine
    assert engine is not None
    assert database._async_session_factory is not None

    disposed = False
    original_dispose = engine.sync_engine.dispose

    def tracking_dispose(*args: object, **kwargs: object) -> None:
        nonlocal disposed
        disposed = True
        original_dispose(*args, **kwargs)

    monkeypatch.setattr(engine.sync_engine, "dispose", tracking_dispose)

    await database.close_db()

    assert disposed, "close_db() must dispose the engine"
    assert database._engine is None
    assert database._async_session_factory is None
