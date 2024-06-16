import os
from streamlit.logger import get_logger

LOGGER = get_logger(__name__)

def get(self, path: str) -> None:
    parts = path.split("/")
    component_name = parts[0]
    component_root = self._registry.get_component_path(component_name)
    if component_root is None:
        self = LOGGER.error("Couldn't find component %s", component_name)
        return
    path = os.path.join(component_root, *parts[1:])
    try:
        with open(path) as f:
            self._set_current_component(f.read())
    except FileNotFoundError:
        LOGGER.error("Couldn't find file %s", path