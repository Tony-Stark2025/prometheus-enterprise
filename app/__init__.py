"""
Zero-duplication compatibility alias package (`app` -> `prometheus`).
Maps all `app.*` imports directly to the canonical `prometheus.*` modules and singletons.
"""

import importlib
import importlib.abc
import importlib.machinery
import sys
import prometheus


class _PrometheusAliasFinder(importlib.abc.MetaPathFinder, importlib.abc.Loader):
    """Dynamically aliases `app.<submodule>` to `prometheus.<submodule>` in `sys.modules`."""

    def find_spec(self, fullname: str, path=None, target=None):
        if fullname == "app" or fullname.startswith("app."):
            prom_name = "prometheus" + fullname[3:]
            prom_spec = importlib.util.find_spec(prom_name)
            if prom_spec is not None:
                return importlib.machinery.ModuleSpec(
                    name=fullname,
                    loader=self,
                    is_package=prom_spec.submodule_search_locations is not None,
                )
        return None

    def load_module(self, fullname: str):
        prom_name = "prometheus" + fullname[3:]
        mod = importlib.import_module(prom_name)
        sys.modules[fullname] = mod
        if "." in fullname:
            parent_name, attr_name = fullname.rsplit(".", 1)
            parent_mod = sys.modules.get(parent_name)
            if parent_mod is not None:
                setattr(parent_mod, attr_name, mod)
        return mod


if not any(isinstance(f, _PrometheusAliasFinder) for f in sys.meta_path):
    sys.meta_path.insert(0, _PrometheusAliasFinder())

# Expose top-level attributes from prometheus
for _k, _v in prometheus.__dict__.items():
    if not _k.startswith("__"):
        globals()[_k] = _v
