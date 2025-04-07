import logging

def get_logger():
    logger = logging.getLogger("cloudmap")
    if not logger.handlers:
        # Create console handler with a higher log level
        ch = logging.StreamHandler()
        ch.setLevel(logging.DEBUG)
        # Create formatter and add it to the handler
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        ch.setFormatter(formatter)
        # Add the handler to the logger
        logger.addHandler(ch)
        logger.setLevel(logging.DEBUG)
    return logger
