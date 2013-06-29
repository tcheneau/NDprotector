"""this module offers functionality to add plugin to NDprotector"""

import sys

# inspired from the wonderful blog post of Armin Ronacher
# http://lucumr.pocoo.org/2006/7/3/python-plugin-system

def init_plugin_path(path):
    """set the path to look for the plugin in the plugin directory"""
    if not path in sys.path:
        sys.path.insert(0, path)


def load_plugins(plugins):
    """imports the plugins that will be used by NDprotector
    (called by the Config.py file)"""
    for plugin in plugins:
        __import__(plugin, None, None, [''])


class Plugin(object):
    """all plugins must inherit this class"""
    capabilities = []


    def __repr__(self):
        return "<%s %r>"\
                % (self.__class__.__name__, self.capabilities)

def find_plugins():
    """returns the loaded plugins"""
    return Plugin.__subclasses__()

def get_plugins_by_capability(capability):
    """return a list of plugins that implements the specified functionality"""
    result = []
    for plugin in Plugin.__subclasses__():
        if capability in plugin.capabilities:
            result.append(plugin)
    return result
