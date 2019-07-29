LOGGING_CONFIG = {
    "version": 1,
    "formatters": {
        "simple": {
            "format": "%(levelname)s - %(message)s",
        },
        "default": {
            "format": "%(levelname)s - %(name)s - %(asctime)s - %(message)s",
        },
    },
    "handlers": {
        "simple_console": {
            "class": "logging.StreamHandler",
            "formatter": "simple",
        },
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "default",
        },
    },
    "loggers": {
        "pygluu.containerlib": {
            "handlers": ["console"],
            "level": "INFO",
            "propagate": False,
        },
    },
    "root": {
        "level": "INFO",
        "handlers": ["console"],
    },
}
