import logging



def setup_logger(name,  level=logging.INFO):
    """
    Function to setup a logger with the specified name and log file.
    :param name: Name of the logger.
    :param log_file: File where the log will be saved.
    :param level: Logging level.
    :return: Configured logger.
    """

    # Create a logger
    logger = logging.getLogger(name)
    logger.setLevel(level)

    handler = logging.StreamHandler()
    handler.setLevel(level)

    # Create a console handler for output to the console

    # Create a formatter and set it for the handlers
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    return logger
