"""
Tests to excercise CWE-117 logging with and without the use of the
``logging-formatter-anticrlf`` module originaly written by dmeyer

see: https://jira.veracode.local/jira/browse/RES-3190
"""

import logging
import sys
import anticrlf


def test_basic_117():
    """
    Pulled from https://stash.veracode.local/users/msheth/repos/core-python/browse/generic_operating_system_services/logging_module_vuln.py

    With minor modifications
    """
    malicious_logging_arg = sys.argv[1]

    logging.basicConfig(filename='malicious.log', level=logging.DEBUG)
    logging.warning(malicious_logging_arg)  # CWEID 117
    logging.debug(malicious_logging_arg)  # CWEID 117
    logging.info(malicious_logging_arg)  # CWEID 117
    logging.error(malicious_logging_arg)  # CWEID 117
    logging.critical(malicious_logging_arg)  # CWEID 117

    logger = logging.getLogger(malicious_logging_arg)
    logger.warning("This is malicious_logger")  # CWEID 117
    logger.debug("This is malicious_logger")  # CWEID 117
    logger.info("This is malicious_logger")  # CWEID 117
    logger.error("This is malicious_logger")  # CWEID 117
    logger.critical("This is malicious_logger")  # CWEID 117


def test_117_cleaned_with_anticrlf():
    malicious_logging_arg = sys.argv[1]

    # --- use a logger to a Stream
    safe_logger_stderr = logging.getLogger(__name__)
    stderr_stream = logging.StreamHandler(sys.stderr)
    stderr_stream.setFormatter(anticrlf.LogFormatter('SAFE %(asctime)s - %(name)s - %(levelname)s - %(message)s'))

    safe_logger_stderr.addHandler(stderr_stream)

    safe_logger_stderr.warning(malicious_logging_arg)
    safe_logger_stderr.debug(malicious_logging_arg)
    safe_logger_stderr.info(malicious_logging_arg)
    safe_logger_stderr.error(malicious_logging_arg)
    safe_logger_stderr.critical(malicious_logging_arg)
    
    # --- Even if the *name* of the logger is tainted, the formatter will cleanse it!
    namesafe_logger_stderr = logging.getLogger(sys.argv[1])
    namesafe_stderr_stream = logging.StreamHandler(sys.stderr)
    namesafe_stderr_stream.setFormatter(anticrlf.LogFormatter('NAME SAFE %(asctime)s - %(name)s - %(levelname)s - %(message)s'))

    namesafe_logger_stderr.addHandler(namesafe_stderr_stream)

    namesafe_logger_stderr.warning(malicious_logging_arg)
    namesafe_logger_stderr.debug(malicious_logging_arg)
    namesafe_logger_stderr.info(malicious_logging_arg)
    namesafe_logger_stderr.error(malicious_logging_arg)
    namesafe_logger_stderr.critical(malicious_logging_arg)

    # --- order doesn't matter, as long as the actuall log calls come AFTER the formatter is set,
    #     you don't have to set the formatter before the addHandler() call. ALL calls after setFormatter() are safe
    safe2_logger_stderr = logging.getLogger(__name__ + 'safe2')
    safe2_stderr_stream = logging.StreamHandler(sys.stderr)

    safe2_logger_stderr.addHandler(safe2_stderr_stream)
    safe2_stderr_stream.setFormatter(anticrlf.LogFormatter('STILL SAFE %(asctime)s - %(name)s - %(levelname)s - %(message)s'))

    safe2_logger_stderr.warning(malicious_logging_arg)
    safe2_logger_stderr.debug(malicious_logging_arg)
    safe2_logger_stderr.info(malicious_logging_arg)
    safe2_logger_stderr.error(malicious_logging_arg)
    safe2_logger_stderr.critical(malicious_logging_arg)

    # --- So here's an example where LogFormatter is called too late
    delay_logger_stderr = logging.getLogger(__name__ + 'delay')
    delay_stderr_stream = logging.StreamHandler(sys.stderr)

    delay_logger_stderr.addHandler(delay_stderr_stream)

    delay_logger_stderr.warning(malicious_logging_arg)  # CWE 117
    delay_logger_stderr.debug(malicious_logging_arg)  # CWE 117
    delay_logger_stderr.info(malicious_logging_arg)  # CWE 117
    delay_logger_stderr.error(malicious_logging_arg)  # CWE 117
    delay_logger_stderr.critical(malicious_logging_arg)  # CWE 117

    # now set the formatter, and the following calls are safe
    delay_stderr_stream.setFormatter(
        anticrlf.LogFormatter('DELAY %(asctime)s - %(name)s - %(levelname)s - %(message)s'))

    delay_logger_stderr.warning(malicious_logging_arg)
    delay_logger_stderr.debug(malicious_logging_arg)
    delay_logger_stderr.info(malicious_logging_arg)
    delay_logger_stderr.error(malicious_logging_arg)
    delay_logger_stderr.critical(malicious_logging_arg)
    
    # --- Different Formatter - Unsafe
    unsafe_logger_stderr = logging.getLogger(__name__ + 'unsafe')
    unsafe_stderr_stream = logging.StreamHandler(sys.stderr)
    unsafe_stderr_stream.setFormatter(logging.Formatter('UNSAFE %(asctime)s - %(name)s - %(levelname)s - %(message)s'))
    unsafe_logger_stderr.addHandler(unsafe_stderr_stream)

    unsafe_logger_stderr.warning(malicious_logging_arg)  # CWE 117
    unsafe_logger_stderr.debug(malicious_logging_arg)  # CWE 117
    unsafe_logger_stderr.info(malicious_logging_arg)  # CWE 117
    unsafe_logger_stderr.error(malicious_logging_arg)  # CWE 117
    unsafe_logger_stderr.critical(malicious_logging_arg)  # CWE 117

    # --- It's unsafe with a file, too, just to be clear
    unsafe_file_logger_log = logging.getLogger(__name__ + 'unsafe_file_file')
    unsafe_file_log_stream = logging.FileHandler('malicious.log')
    unsafe_file_log_stream.setFormatter(logging.Formatter('UNSAFE FILE %(asctime)s - %(name)s - %(levelname)s - %(message)s'))
    unsafe_file_logger_log.addHandler(unsafe_file_log_stream)

    unsafe_file_logger_log.warning(malicious_logging_arg)  # CWE 117
    unsafe_file_logger_log.debug(malicious_logging_arg)  # CWE 117
    unsafe_file_logger_log.info(malicious_logging_arg)  # CWE 117
    unsafe_file_logger_log.error(malicious_logging_arg)  # CWE 117
    unsafe_file_logger_log.critical(malicious_logging_arg)  # CWE 117


if __name__ == '__main__':
    test_basic_117()
    test_117_cleaned_with_anticrlf()