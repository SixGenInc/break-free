import argparse
from argparse import RawTextHelpFormatter
import struct
import sys

# Module imports
from modules.log import set_level, get_logger
from modules.online import bits_to_dict, check, PortQuiz

VERSION = '1.0'

MAX_PORTS = 8  # The number of available ports for direct connection 
               # to succeed before stopping the port checks

BANNER = '''
              ./.                                                                                   
           :odmhmms:`                                                                               
       .+hNho-   .+hNh+.                                                                            
   `:smms:` `:sds:  `:smms:`                                                                        
  yNh+.  .+hNdo/o:`:+.  .+hNs                                                                       
  dN  -smNy/.  .+hNdhNms-  Nd      .--------` --  --`      `--   `-------  `---------  :`      `:.  
  dN  hMd/`   `+y/` `/mMy  Nd    .mNhyyyyyyy. Nm  -yNs.  `oNy- /dNhyyyyyy` +Mdyyyyyys :MMs.    -Mo  
  dN  hMddNh+.   -ohNdo-   Nd    /My```````   Nm    .yNyoNy.  /My` ``````` +M/ `````` :MyyNs.  -Mo  
  dN  hMo `/yNmhmNy/` `/+  Nd     :syyyyyhdm: Nm     .hNMh.   sM:  oyyyhMh +M/-yyyyy: :Mo -yNy.-Mo  
  dN  /hNdo-  -+-  -odMMh  Nd             -My Nm   .yNo`.sNy- .mm:`    .Mh +M+        :Mo   -yMdMo  
  dN  ` `:smNy/./yNms:sMh  Nd    :mmmmmmmmmy. md .smo`    `smy.`+hmmmmmmNy /NNmmmmmmd -N+     .yN/  
  dN  hdo-  .+hNh+.  -hMy  Nd                                                                       
  dN` `:smNy/.   ./yNms:  `Nd                                                                       
  /hNh+.  .+hNdymNh+.  `/ymd+                                                                       
    `:smms:` `:o:   -odNy/`                                                                         
        .+hNh+. ./yNdo-                                                                             
           `:smNmy/`                                                                                
               `         
                                https://sixgen.io

               Break Free - Network Exfiltration Tester - v{}                                      
'''.format(VERSION)

#############################################
#                                           #
#  Data object classes                      #
#                                           #
#############################################

class Session(object):

    def __init__(self):
        self.system_info = None
        self.online_status = None
        self.open_ports = {}
        self.egress_ports = set()

    def __repr__(self):
        return '{{SESSION {}}}'.format(
            self.system_info or ''
        )

class OnlineStatus(object):

    __slots__ = ('offset', 'mintime', 'register')

    def __init__(self, offset=None, mintime=None, register=None):
        if register is None or mintime is None:
            offset, mintime, register = online.check()

        self.offset = offset
        self.mintime = mintime
        self.register = register

    def get_dict(self):
        result = bits_to_dict(self.register)
        if self.mintime == 65535:
            result.update({
                'mintime': 'MAX'
            })
        else:
            result.update({
                'mintime': '{:.3f}s'.format(float(self.mintime)/1000)
            })

        if result['ntp']:
            if self.offset in (32767, -32768):
                word = 'MAX'
                if self.offset < 0:
                    word = 'MIN'

                result.update({
                    'ntp-offset': word
                })
            else:
                result.update({
                    'ntp-offset': '{:.3f}s'.format(float(self.offset)/1000000)
                })
        else:
            result.update({
                'ntp-offset': 'N/A'
            })

        return result

    def __str__(self):
        return '{{ONLINE: {}}}'.format(
            ' '.join(
                '{}={}'.format(
                    k.upper(),
                    v if type(v) in (int,str,unicode,bool) else any([
                        x for x in v.itervalues()
                    ])) for k,v in self.get_dict().iteritems()))

class PortQuizPort(object):

    __slots__ = ('ports')

    def __init__(self, ports):
        self.ports = [int(x) for x in ports]

    def __str__(self):
        return '{{PORTQUIZ: {}}}'.format(','.join(str(x) for x in sorted(self.ports)))

#############################################
#                                           #
#  cmdline functions                        #
#                                           #
#############################################

class colors:
    HEADER = '\033[95m' if 'win32' not in sys.platform else ''
    OKBLUE = '\033[94m' if 'win32' not in sys.platform else ''
    OKGREEN = '\033[92m' if 'win32' not in sys.platform else ''
    WARNING = '\033[93m' if 'win32' not in sys.platform else ''
    FAIL = '\033[91m' if 'win32' not in sys.platform else ''
    ENDC = '\033[0m' if 'win32' not in sys.platform else ''


def parse_arguments():
    parser = argparse.ArgumentParser(description=BANNER, formatter_class=RawTextHelpFormatter)
    output_level = parser.add_mutually_exclusive_group(required=False)
    output_level.add_argument('-v', '--verbose', dest='verbose', required=False,
                        help='Set logging level to DEBUG', action='store_true')
    output_level.add_argument('-q', '--quiet', dest='quiet', required=False,
                        help='Disable logging', action='store_true')
    parser.add_argument('-m', '--max-ports', dest='max_ports', required=False,
                        help='The number of available ports for direct connection\nto succeed before stopping the port checks', 
                        type=int, default=MAX_PORTS)
    # TODO set connect and http_timeouts for PortQuiz?
    args = parser.parse_args()
    return args


def main():
    # Get all args
    args = parse_arguments()

    # Logging setup
    if args.verbose:
        set_level(verbose=True)
    elif args.quiet:
        set_level(silent=True)
    else:
        set_level()

    logger = get_logger('main')
    logger.info('Trying to break free - please wait')
    session = Session()

    logger.debug('Starting PortQuiz')
    portquiz = PortQuiz(amount=args.max_ports)
    portquiz.start()

    logger.debug('Starting Online checks')
    try:
        offset, mintime, register = check()
        logger.debug('OnlineStatus completed: %04x %04x %08x',
                      offset, mintime, register)
        online_status_obj = OnlineStatus(offset, mintime, register)
        session.online_status = online_status_obj.get_dict()
    except Exception, e:
        logger.exception('Online status check failed: {}'.format(e))

    logger.debug('Waiting for PortQuiz completion')
    portquiz.join()
    logger.debug('PortQuiz completed')

    try:
        if portquiz.available:
            port_quiz_port_obj = PortQuizPort(portquiz.available)
            logger.debug(port_quiz_port_obj)
            for port in port_quiz_port_obj.ports:
                session.egress_ports.add(port)
    except Exception, e:
        logger.exception(e)

    logger.debug('Checks completed')
    print_results(logger, session)


def print_results(logger, session):
    logger.info('\n')
    logger.info('{:^25}'.format('ONLINE STATUS'))
    logger.info('=========================')

    if session.online_status:

        for key in [ 'online', 'igd', 'dns', 'ntp',
                'direct-dns', 'http', 'https', 'https-no-cert',
                'stun', 'mintime', 'ntp-offset']:
            if session.online_status[key]:
                logger.info('{}{:<20}{}{}'.format(colors.OKGREEN,
                                        key.upper().replace('-', ' '), 
                                        str(session.online_status[key]).upper(), 
                                        colors.ENDC))
            else:
                logger.info('{}{:<20}{}{}'.format(colors.FAIL, 
                                        key.upper().replace('-', ' '),
                                        str(session.online_status[key]).upper(), 
                                        colors.ENDC))
        # Reverse color logic
        for key in ['https-mitm', 'proxy', 'transparent-proxy', 'hotspot']:
            if not session.online_status[key]:
                logger.info('{}{:<20}{}{}'.format(colors.OKGREEN,
                                        key.upper().replace('-', ' '), 
                                        str(session.online_status[key]).upper(), 
                                        colors.ENDC))
            else:
                logger.info('{}{:<20}{}{}'.format(colors.FAIL, 
                                        key.upper().replace('-', ' '),
                                        str(session.online_status[key]).upper(), 
                                        colors.ENDC))

        logger.info('\n')
        logger.info('{:^40}'.format('PASTES STATUS'))
        logger.info('========================================')
        for key, value in session.online_status['pastebins'].iteritems():
            if value:
                logger.info('{}{:<35}{}{}'.format(colors.OKGREEN, key, value, colors.ENDC))
            else:
                logger.info('{}{:<35}{}{}'.format(colors.FAIL, key, value, colors.ENDC))

    if session.egress_ports:
        ordered_ports = sorted(session.egress_ports)
        logger.info('\nEGRESS PORTS: {}{}{}'.format(colors.OKGREEN, ordered_ports, colors.ENDC))
    else:
        logger.info('\n{}NO EGRESS PORTS FOUND{}'.format(colors.FAIL, colors.ENDC))

    logger.info('\n')

    if 'win32' in sys.platform:
        # Keep the window open on Windows
        raw_input('Press any key to continue (will close the window if run via double-click)')

if __name__ == "__main__":
    main()
