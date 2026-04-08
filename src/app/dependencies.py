from typing import Annotated

from fastapi import Depends

from src.app.config import Settings, get_settings

SettingsDep = Annotated[Settings, Depends(get_settings)]
