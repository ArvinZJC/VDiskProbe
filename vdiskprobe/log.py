# Copyright (c) 2026 IsArvin.
# This file is part of VDiskProbe. Please refer to the LICENCE file for licence information.

"""Logging helpers for VDiskProbe."""

import logging

LOGGER_NAME = "vdiskprobe"
NullHandler = logging.NullHandler


def _get_root_logger() -> logging.Logger:
    """Return the package root logger.

    Returns
    -------
    logging.Logger
        Root ``vdiskprobe`` logger with a null handler attached.
    """
    logger = logging.getLogger(LOGGER_NAME)
    for handler in logger.handlers:
        if isinstance(handler, NullHandler):
            return logger
    logger.addHandler(NullHandler())
    return logger


def get_logger(name: str | None = None) -> logging.Logger:
    """Return a VDiskProbe logger.

    Parameters
    ----------
    name : str, optional
        Child logger suffix.

    Returns
    -------
    logging.Logger
        Logger instance.
    """
    if not name:
        return _get_root_logger()
    return logging.getLogger("{0}.{1}".format(LOGGER_NAME, name))


def configure_logging(
    level: int | None = logging.INFO, stream: object = None, propagate: bool = False
) -> logging.Logger:
    """Configure the VDiskProbe root logger.

    Parameters
    ----------
    level : int, optional
        Logging level to apply.
    stream : object, optional
        Output stream used by the stream handler.  Ignored when
        *propagate* is *True*.
    propagate : bool, optional
        When *True*, remove null and package stream handlers and enable propagation
        so that VDiskProbe logs flow to ancestor loggers.  No stream
        handler is added — the integrator is expected to configure
        their own handlers on an ancestor logger.  When *False*
        (default), a stream handler is attached and propagation stays
        disabled.

    Returns
    -------
    logging.Logger
        Configured root logger.
    """
    if level is None:
        level = logging.INFO
    logger = _get_root_logger()
    if propagate:
        logger.propagate = True
        for handler in list(logger.handlers):
            if isinstance(handler, NullHandler) or getattr(handler, "_vdiskprobe_handler", False):
                logger.removeHandler(handler)
    else:
        logger.propagate = False
        active_handler = None
        for handler in logger.handlers:
            if getattr(handler, "_vdiskprobe_handler", False):
                active_handler = handler
                break
        if active_handler is None:
            active_handler = logging.StreamHandler(stream)
            setattr(active_handler, "_vdiskprobe_handler", True)
            active_handler.setFormatter(logging.Formatter("%(asctime)s %(name)s [%(levelname)s] %(message)s"))
            logger.addHandler(active_handler)
    logger.setLevel(level)
    return logger


_get_root_logger()
