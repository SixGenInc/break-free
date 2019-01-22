import logging

def set_level(verbose=False, silent=False):
    if verbose:
        logger = logging.getLogger('Break Free')
        FORMAT = '[%(filename)10s:%(lineno)-4s - %(funcName)10s() ] %(message)s'
        logging.basicConfig(format=FORMAT)
        logger.setLevel(logging.DEBUG)
    elif silent:
        # TODO supress all output
        logger.setLevel(51)
        pass
    else:
        logger = logging.getLogger('Break Free')
        FORMAT = '%(message)s'
        logging.basicConfig(format=FORMAT)
        logger.setLevel(logging.INFO)

def get_logger(name):
    logger = logging.getLogger('Break Free')
    return logger.getChild(name)
