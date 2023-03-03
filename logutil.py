import logging
import logging.handlers
import platform
import os
import sys
# -----------------------------------------------------------------------------------------------------------------------------
def _set_formatter(mp=False):
    prefix = platform.node().split('.', 1)[0]
    if mp:
        prefix += ":" + str(os.getpid())
    fmtr = logging.Formatter(prefix + ':%(asctime)s:%(levelname)s: %(message)s')
    for handler in logging.getLogger().handlers:
        handler.setFormatter(fmtr)

#-----------------------------------------------------------------------------------------------------------------------------
def set_logging (*, log_file=None, level=logging.INFO, max_bytes=4*1024*1024, backup_count=5, mp=False):
    '''
    Setup the logging configuration. Must be called before any logging output is produced.
    :param log_file: Full path to the log_file or a dir. If dir is passed, log file is (None - to not to log to file)
    :param level: logging level
    :param max_bytes: Configuration for rotating log - max file size
    :param backup_count: Configuration for rotating log - max number of log files (suffixed .log.1, .log.2, ...)
    :param log_threadname: Add name of thread to logging header - useful for Multi-threaded programs.
    :return: root logger
    '''
    logger = logging.getLogger()
    if len(logger.handlers):
        logger.handlers = []

    logger.setLevel(level)

    # add stream or ipython notebook handler
    handler_list = []
    handler_list.append(logging.StreamHandler())

    if log_file is not None:
        base = os.path.splitext(os.path.basename(sys.argv[0]))[0]
        base_log = base + '.log'
        if os.path.isdir(log_file):
            log_file = os.path.join(log_file, base_log)
        elif log_file.endswith("_"):
            # treat it as prefix
            log_file = log_file + base_log
        else:
            assert log_file.endswith(".log"), f"ERROR: Invalid logfile extension {log_file} - must end with .log or _ or should be a dir"

        # setup rotating file handler
        print("Logging to: {}".format(log_file))
        handler_list.append(logging.handlers.RotatingFileHandler(log_file, 'a',
                                                                  maxBytes=max_bytes, backupCount=backup_count))
    for ch in handler_list:
        ch.setLevel(level)
        logger.addHandler(ch)

    _set_formatter(mp=mp)
    return logger
