import logging

# No need for a name in the format, as the file already tells us which logger
# is responsible.
LOG_FORMATTER = logging.Formatter('[%(asctime)s | %(levelname)s]: %(message)s')

def setup_file_logger(
        logger_name, 
        file_to_log_to, 
        logging_level = logging.DEBUG,
        log_formatter = LOG_FORMATTER
    ):
    """
    Creates a logger that logs to the specified file at the specified level.

    :param logger_name: The name of the logger. Can be used in the Formatter to
        display the name of the used logger.

    :param file_to_log_to: Relative or absolute path to the file that contains the
        log

    :param logging_level: The lowest level of logging information that is to be
        written to the log file. Defaults to logging.DEBUG
    
    :param log_formatter: The Formatter, that specifies the format of the written
        logs. Defaults to a Formatter with the format '[time | level] message'
    
    :return: Logger object fitting the supplied arguments
    """

    clear_log(file_to_log_to)

    handler = logging.FileHandler(file_to_log_to, mode = 'a')
    handler.setFormatter(log_formatter)

    logger = logging.getLogger(logger_name)
    logger.setLevel(logging_level)
    logger.addHandler(handler)

    return logger

def clear_log(log_file):
    """
    Clears the supplied log_file if it exists, else does nothing

    :param log_file: Relative or absolute path to the file that is to be cleared.
    """

    try:
        # This clears the log file, if it exists.
        opened_log_file = open(log_file, 'w')
    except FileNotFoundError:
        return
    
    opened_log_file.close()

# Logs are always created at the current working directory of the python file that
# uses the loggers. If a path is supplied however, this behaviour can be changed.
# This here uses a relative path. If .. would be left out, the code tries to find
# the supplied location from system root.
# WARN: SELinux could be problematic here.
saml_logger = setup_file_logger("SAML-Logger", "/home/nruntemund/ba_program/logs/saml-eval.log")
oidc_logger = setup_file_logger("OIDC-Logger", "/home/nruntemund/ba_program/logs/oidc-eval.log")
