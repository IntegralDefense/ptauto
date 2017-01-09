import os
import configparser
import logging

from lib.pt.common.constants import PT_HOME
from lib.pt.common.objects import Dictionary

log = logging.getLogger()

class Config:
    """Configuration file parser."""

    def __init__(self, file_name="pt", cfg=None):
        """
        @param file_name: file name without extension.
        @param cfg: configuration file path.
        """
        config = configparser.ConfigParser()

        if cfg is not None:
            log.debug('Reading config: {}'.format(cfg))
            config.read(cfg)
        else:
            log.debug('Reading config: {}'.format(os.path.join(PT_HOME, "etc", "local", "%s.ini" % file_name)))
            config.read(os.path.join(PT_HOME, "etc", "local", "%s.ini" % file_name))

        self.fullconfig = config._sections

        for section in config.sections():
            setattr(self, section, Dictionary())
            for name, raw_value in config.items(section):
                try:
                    # Ugly fix to avoid '0' and '1' to be parsed as a
                    # boolean value.
                    # We raise an exception to goto fail^w parse it
                    # as integer.
                    if config.get(section, name) in ["0", "1"]:
                        raise ValueError

                    value = config.getboolean(section, name)
                except ValueError:
                    try:
                        value = config.getint(section, name)
                    except ValueError:
                        value = config.get(section, name)

                setattr(getattr(self, section), name, value)


    def get(self, section):
        """Get option.
        @param section: section to fetch.
        @return: option value.
        """
        return getattr(self, section)

    def get_config(self):
        return self.fullconfig
