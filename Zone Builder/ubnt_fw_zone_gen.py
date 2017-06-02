#!/usr/bin/env python
#
# vyatta_firewall_builder.py - Build a zone-based IPv4/IPv6 firewall for Vyatta
#
# -*- coding: utf-8 -*-

version = '1.8.0'

import argparse
import itertools
import re
import subprocess as sp
import sys
import yaml

user_opts = None

# Holds zones and which interfaces reside in each. Zones named 'int' and
# 'ext' are required
#
# yapf: disable
zones = {}

# Holds Groups which can be used in rules
# Note that Comcast distributes ipv6 from 'fe80::/10' - so do not add this to the bogon list
fw_groups = {}

# Holds the list of rules to create. Each rule has the following elements:
#
# (
# source zone or list of source zones,
# dest zone or list of dest zones,
# list of parameters,
# list of ip versions (optional, defaults to [4, 6]),
# rulenum (optional, defaults to natural order)
# )
#

# yapf: disable

rules = []

class switch(object):

    def __init__(self, value):
        self.value                                          = value
        self.fall                                           = False

    def __iter__(self):
        #Return the match method once, then stop
        yield self.match
        raise StopIteration

    def match(self, *args):
        #Indicate whether or not to enter a case suite
        if self.fall or not args:
            return True
        elif self.value in args:  # changed for v1.5, see below
            self.fall = True
            return True
        else:
            return False

# Counters to determine rule numbers for rules without explicit rule numbers
#
ruleset_counters = {}

commands         = []

# Used to update firewall rules automatically
vyatta_cmd_normal = "/opt/vyatta/sbin/vyatta-cfg-cmd-wrapper"

# Used when debug flag is specified to test rule update commandlines
vyatta_cmd_debug  = "echo"

def get_args():
    # Enable default logging (rule 10000)
    # Defaulted to log all non-matching dropped packets
    #
    # global default_log
    # default_log                                           = user_opts.default_log

    # Set this to False unless you want to generate and write to your config.boot file
    #
    # update_config_boot                                    = user_opts.update_config_boot

    parser           = argparse.ArgumentParser(
        description  =
        'Build a zone-based IPv4/IPv6 firewall configuration for Vyatta.',
        epilog       =
        'If [-l/-log] isn\'t set, enable-default-log will be disabled for all rulesets. If [-U/-Update] isn\'t set, %(prog)s prints to STDOUT.')

    parser.add_argument(
        '-U',
        '-Update',
        action       = "store_true",
        dest         ='update_config_boot',
        help         =
        'Directly update firewall configuration, commit and save config.boot - CAUTION, only use this option if you know your proposed firewall configuration is correct.')

    parser.add_argument(
        '-l',
        '-log',
        action       = "store_true",
        dest         ='default_log',
        help         =
        'Sets enable-default-log option on built-in rule 10000 for each rule set. Any dropped packets unmatched by your rule set will be logged.')

    parser.add_argument(
        '-v',
        '-version',
        action       = 'version',
        help         ='Show %(prog)s version and exit.',
        version      = '%(prog)s {}'.format(version))

    parser.add_argument(
        '-D',
        '-debug',
        action      = "store_true",
        dest        = 'debug',
        help        =
        "Enables debuging mode which only outputs commands to stdout and doesn't execute them.")

    parser.add_argument(
        '-f',
        '-file',
        action      = "store",
        required    = True,
        dest        = 'file',
        help        =
        'Name of the YAML file to be used to generate the firewall rules.')

    return parser.parse_args()


def parse_rules_file(rule_file):
    global zones, fw_groups, rules, all_zones, all_groups

    with open(rule_file, 'r') as f:
        yml = yaml.load(f)

    zones = yml['zones']
    fw_groups = yml['fw_groups']
    rules = yml['rules']

    # Build list of all zone names, which can be used in rules
    all_zones = zones.keys()
    all_zones.append('loc')

    # Builds list of all groups, which can be used in rules
    all_groups = fw_groups.keys()


def yesno(*args):

    if len(args) > 1:
        default                                             = args[0].strip().lower()
        question                                            = args[1].strip()
    elif len(args) == 1:
        default                                             = args[0].strip().lower()
        question                                            = 'Answer y or n:'
    else:
        default                                             = None
        question                                            = 'Answer y or n:'

    if default == None:
        prompt                                              = " [y/n] "
    elif default == "y":
        prompt                                              = " [Y/n] "
    elif default == "n":
        prompt                                              = " [y/N] "
    else:
        raise ValueError(
            "{} invalid default parameter: \'{}\' - only [y, n] permitted".format(
                __name__, default))

    while 1:
        sys.stdout.write(question + prompt)
        choice                                              = (raw_input().lower().strip() or '')
        if default is not None and choice == '':
            if default == 'y':
                return True
            elif default == 'n':
                return False
        elif default is None:
            if choice == '':
                continue
            elif choice[0] == 'y':
                return True
            elif choice[0] == 'n':
                return False
            else:
                sys.stdout.write("Answer must be either y or n.\n")
        elif choice[0] == 'y':
            return True
        elif choice[0] == 'n':
            return False
        else:
            sys.stdout.write("Answer must be either y or n.\n")

def sub_vars(var_str):
    for case in switch(var_str):
        if case('$all_zones'):
            return all_zones
            break

        if case('$all_groups'):
            return all_groups
            break


def build_rule(src_zone, dst_zone, params, ipversions = [4, 6], rulenum=None):
    '''
    Build a rule for each applicable zone direction and IP version
    '''
    # If zones are passed as simple strings, convert to tuples
    if isinstance(src_zone, str):
        if src_zone[:1] == "$":
            src_zone = sub_vars(src_zone)
        else:
            src_zone                                        = (src_zone,)

    if isinstance(dst_zone, str):
        if dst_zone[:1] == "$":
          dst_zone = sub_vars(dst_zone)
        else:
          dst_zone                                          = (dst_zone,)

    if isinstance(params, str):
        raise TypeError("params must be a list or tuple")

    # All combinations of source -> dest
    for source, dest in itertools.product(src_zone, dst_zone):
        if source == dest:
            continue
        ruleset                                             = '%s-%s' % (source, dest)

        # Check/update counter for ruleset if rulenum is omitted
        if rulenum:
            ruleid                                          = rulenum
        else:
            if not ruleset in ruleset_counters:
                ruleset_counters[ruleset]                   = 0
            ruleset_counters[ruleset] += 1
            ruleid                                          = ruleset_counters[ruleset]
        for ipversion in ipversions:
            if ipversion == 4:
                name_param                                  = 'name'
                set_name                                    = ruleset
            else:
                name_param                                  = 'ipv6-name'
                set_name                                    = 'ipv6-' + ruleset
            base_cmd                                        = "set firewall %s %s rule %s" % (name_param, set_name,
                                                       ruleid)
            commands.append(base_cmd)
            for param in params:
                commands.append(base_cmd + " " + param)


if __name__ == '__main__':
    user_opts = get_args()

    parse_rules_file(user_opts.file)

    commands.append("delete firewall group")
    commands.append("delete firewall name")
    commands.append("delete firewall ipv6-name")
    commands.append("delete zone-policy")

    for a in all_groups:
        for case in switch(a):
            if case('port_group'):
                dkey                                        = 'ports'
                gtype                                       = 'port-group'
                gtarget                                     = 'port'
                break

            if case('address_group'):
                dkey                                        = 'addresses'
                gtype                                       = 'address-group'
                gtarget                                     = 'address'
                break

            if case('ipv4_group'):
                dkey                                        = 'addresses'
                gtype                                       = 'network-group'
                gtarget                                     = 'network'
                break

            if case('ipv6_group'):
                dkey                                        = 'addresses'
                gtype                                       = 'ipv6-network-group'
                gtarget                                     = 'ipv6-network'
                break

        for b in fw_groups[a].keys():
            commands.append("set firewall group %s %s description '%s'" %
                            (gtype, b, fw_groups[a][b]['description']))

            for c in fw_groups[a][b][dkey]:
                commands.append(
                    "set firewall group %s %s %s %s" % (gtype, b, gtarget, c))

    # Build a ruleset for every direction (eg: 'int-ext', 'ext-dmz', 'ext-loc', etc.)
    rulesets                                                = list(itertools.permutations(all_zones, 2))

    # Create rulesets for all directions
    for src, dest in rulesets:
        for prefix in ('', 'ipv6-'):
            if user_opts.default_log:
                commands.append(
                    "set firewall %sname %s%s-%s enable-default-log" %
                    (prefix, prefix, src, dest))
            commands.append(
                "set firewall %sname %s%s-%s" % (prefix, prefix, src, dest))
            commands.append("set firewall %sname %s%s-%s default-action drop" %
                            (prefix, prefix, src, dest))

    # Add rules
    for rule in rules:
        build_rule(**rule)

    # Create zones
    for zone in all_zones:
        # Create zone
        if not zone == 'loc':
            commands.append("set zone-policy zone %s description '%s'" %
                            (zone, zones[zone]['description']))
            commands.append(
                "set zone-policy zone %s default-action drop" % zone)
            # Add interfaces
            for interface in zones[zone]['interfaces']:
                commands.append(
                    "set zone-policy zone %s interface %s" % (zone, interface))
#       elif zone == 'loc':
        else:
            # Configure local zone
            commands.append(
                "set zone-policy zone %s default-action drop" % zone)
            commands.append("set zone-policy zone %s local-zone" % zone)

        # Set rulesets
        for srczone in all_zones:
            if srczone == zone:
                continue
            for prefix in ('', 'ipv6-'):
                commands.append(
                    "set zone-policy zone %s from %s firewall %sname %s%s-%s" %
                    (zone, srczone, prefix, prefix, srczone, zone))

    # Remove duplicates
    seen = set()
    result = []
    for item in commands:
        if item not in seen:
            seen.add(item)
            result.append(item)
    commands = result

    if user_opts.update_config_boot and yesno(
            'y', 'OK to update your configuration?'):  # Open a pipe to bash and iterate commands

        commands[:0]                                        = ["begin"]
        commands.append("commit")
        commands.append("save")
        commands.append("end")

        if user_opt['debug']:
            vyatta_cmd = vyatta_cmd_debug
        else:
            vyatta_cmd = vyatta_cmd_normal

        vyatta_shell                                        = sp.Popen(
            'bash',
            shell=True,
            stdin                                           = sp.PIPE,
            stdout=sp.PIPE,
            stderr                                          = sp.PIPE)
        for cmd in commands:  # print to stdout
            print cmd
            vyatta_shell.stdin.write('{} {};\n'.format(vyatta_cmd, cmd))

        out, err                                            = vyatta_shell.communicate()

        cfg_error                                           = False
        if out:
            if re.search(r'^Error:.?', out):
                cfg_error                                   = True
            print "configure message:"
            print out
        if err:
            cfg_error                                       = True
            print "Error reported by configure:"
            print err
        if (vyatta_shell.returncode == 0) and not cfg_error:
            print "Zone firewall configuration was successful."
        else:
            print "Zone firewall configuration was NOT successful!"

    else:
        for cmd in commands:
            print cmd
