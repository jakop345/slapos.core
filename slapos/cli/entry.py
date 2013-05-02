# -*- coding: utf-8 -*-

import logging
import sys

import cliff
import cliff.app
import cliff.commandmanager

import slapos.version


class SlapOSCommandManager(cliff.commandmanager.CommandManager):

    def find_command(self, argv):
        """Given an argument list, find a command and
        return the processor and any remaining arguments.
        """
        # XXX a little cheating, 'slapos node' is not documented
        #     by the help command
        if argv == ['node']:
            argv = ['node', 'status']

        search_args = argv[:]
        name = ''
        while search_args:
            if search_args[0].startswith('-'):
                raise ValueError('Invalid command %r' % search_args[0])
            next_val = search_args.pop(0)
            name = '%s %s' % (name, next_val) if name else next_val
            if name in self.commands:
                cmd_ep = self.commands[name]
                cmd_factory = cmd_ep.load()
                return (cmd_factory, name, search_args)
        else:
            print >>sys.stderr, ('The command %r does not exist or is not yet implemented.\n'
                                 'Please have a look at http://community.slapos.org to read documentation or forum.\n'
                                 'Please also make sure that SlapOS Node is up to date.' % (argv,))
            sys.exit(5)


class SlapOSApp(cliff.app.App):

    #
    # self.options.verbose_level:
    #    -q  -> 0 (WARNING)
    #        -> 1 (INFO)
    #    -v  -> 2 (DEBUG)
    #    -vv -> 3 (...)
    #    etc.
    #

    log = logging.getLogger(__name__)

    def __init__(self):
        super(SlapOSApp, self).__init__(
            description='SlapOS client %s' % slapos.version.version,
            version=slapos.version.version,
            command_manager=SlapOSCommandManager('slapos.cli'),
        )

    def build_option_parser(self, *args, **kw):
        kw.setdefault('argparse_kwargs', {})
        kw['argparse_kwargs']['conflict_handler'] = 'resolve'
        parser = super(SlapOSApp, self).build_option_parser(*args, **kw)

        # add an alias for --log-file
        parser.add_argument(
            '--log-file', '--logfile',
            action='store',
            default=None,
            help='Specify a file to log output. Disabled by default.',
        )

        # always show tracebacks on errors
        parser.set_defaults(debug=True)

        return parser

    def initialize_app(self, argv):
        if self.options.verbose_level > 2:
            self.log.debug('initialize_app')

    def prepare_to_run_command(self, cmd):
        if self.options.verbose_level > 2:
            self.log.debug('prepare_to_run_command %s', cmd.__class__.__name__)

    def clean_up(self, cmd, result, err):
        if self.options.verbose_level > 2:
            self.log.debug('clean_up %s', cmd.__class__.__name__)

        if err:
            self.log.debug('got an error: %s', err)


def main(argv=sys.argv[1:]):
    app = SlapOSApp()
    if not argv:
        argv = ['-h']
    return app.run(argv)


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
