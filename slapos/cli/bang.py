# -*- coding: utf-8 -*-

import logging

from slapos.cli.config import ConfigCommand
from slapos.bang import do_bang


class BangCommand(ConfigCommand):

    log = logging.getLogger(__name__)

    def get_parser(self, prog_name):
        parser = super(BangCommand, self).get_parser(prog_name)
        parser.add_argument('-m', '--message',
                            help='Message for bang')
        return parser

    def take_action(self, args):
        config = self.fetch_config(args)
        do_bang(config, args.message)
