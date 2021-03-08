LOGGING_CONFIG = {
    "version": 1,
    "formatters": {
        "default": {
            "format": "%(levelname)s - %(name)s - %(asctime)s - %(message)s",
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "default",
        },
    },
    "loggers": {
        "pygluu.containerlib": {
            "handlers": ["console"],
            "level": "INFO",
            "propagate": True,
        },
        "entrypoint": {
            "handlers": ["console"],
            "level": "INFO",
            "propagate": False,
        },
        "v315": {
            "handlers": ["console"],
            "level": "INFO",
            "propagate": False,
        },
        "v316": {
            "handlers": ["console"],
            "level": "INFO",
            "propagate": False,
        },
        "v40": {
            "handlers": ["console"],
            "level": "INFO",
            "propagate": False,
        },
        "v41": {
            "handlers": ["console"],
            "level": "INFO",
            "propagate": False,
        },
        "v42": {
            "handlers": ["console"],
            "level": "INFO",
            "propagate": False,
        },
        "v43": {
            "handlers": ["console"],
            "level": "INFO",
            "propagate": False,
        },
    },
}
