#!/usr/bin/env python
# -*- coding: utf-8 -*-

try:
    from .config import Configuration
except (ValueError, ImportError) as e:
    raise Exception("You may need to run defite from the root directory", e) from e


from .util.color import Color

import os
import subprocess

User_Input=None

class Defite(object):

    def __init__(self):
        """
        Initializes defite.
        Checks that its running under *nix, with root permissions and ensures dependencies are installed.
        """

        self.print_banner()

        Configuration.initialize(load_interface=False)

        if os.name == 'nt':
            Color.pl('{!} {R}error: {O}defite{R} must be run under a {O}*NIX{W}{R} like OS')
            Configuration.exit_gracefully(0)
        if os.getuid() != 0:
            Color.pl('{!} {R}error: {O}defite{R} must be run as {O}root{W}')
            Color.pl('{!} {R}re-run with {O}sudo{W}')
            Configuration.exit_gracefully(0)

        from .tools.dependency import Dependency
        Dependency.run_dependency_check()

    def start(self):
        """
        Starts target-scan + attack loop, or launches utilities depending on user input.
        """
        if True:
            Configuration.get_monitor_mode_interface()
            self.scan_and_attack()

    @staticmethod
    def print_banner():
        """Displays ASCII art of the highest caliber."""
        Color.pl('')
        Color.pl(r'{GR}            *                  *          ')      
        Color.pl(r'           ***                ***              ')
        Color.pl(r'          **  ***          ***  **             ')
        Color.pl(r'         **  **   *{BR}|    |{BR}{GR}*   **  **            ')
        Color.pl(r'        **  **  ***  **  ***  **  **     {W}Defite {G}%s{GR}' % Configuration.version )
        Color.pl(r'        **  *   **  {BR}|--|{BR}{GR}  **  **  **     {W}Wifi Deauthentication Tool{GR}')
        Color.pl(r'        **  **  **  {BR}|--|{BR}{GR}  **  **  **     {W}Modified by {C}Raiden Ray{GR}')
        Color.pl(r'        **  **   **  **   **  **  **           ')
        Color.pl(r'         **  **   *{BR}|    {BR}|{GR}*{GR}   **{GR}  **{GR}{BR}            ')
        Color.pl(r'          {GR}**  ***{GR}  {BR}--  --{BR}  {GR}***{GR}  **{GR}{BR}             ')
        Color.pl(r'           {GR}***{GR}    {BR}//    \\{BR}    {GR}***{GR}{BR}              ')
        Color.pl(r'            {GR}*{GR}    {BR}//      \\{BR}{GR}   *{BR}                ')
        Color.pl(r'                {BR}{BR}//        \\{BR}{BR}                   ')
        Color.pl(r'               {BR}{BR}//          \\{BR}{BR}                   ')
        Color.pl(r'              {BR}{BR}//            \\{BR}{BR}                  ')
        Color.pl(r'             {BR}{BR}/                \{BR}{BR}                 ')
        


    @staticmethod
    def scan_and_attack():
        """
        1) Scans for targets, asks user to select targets
        2) Attacks each target
        """
        from .util.scanner import Scanner
        from .attack.all import AttackAll

        Color.pl('')

        # Scan
        s = Scanner()
        do_continue = s.find_targets()
        targets = s.select_targets()

        # # Ask For Attack Duration
        # Color.pl(r'{R} Enter Attack Duration Time (Minute) - {R}')
        # user= int(input())
        # user=Configuration.wpa_attack_timeout*60


        if Configuration.infinite_mode:
            while do_continue:
                AttackAll.attack_multiple(targets)
                do_continue = s.update_targets()
                if not do_continue:
                    break
                targets = s.select_targets()
            attacked_targets = s.get_num_attacked()
        else:
            # Attack
            attacked_targets = AttackAll.attack_multiple(targets)

        Color.pl('{+} Finished attacking {C}%d{W} target(s), exiting' % attacked_targets)


def entry_point():
    try:
        defite = Defite()
        defite.start()
    except Exception as e:
        Color.pexception(e)
        Color.pl('\n{!} {R}Exiting{W}\n')

    except KeyboardInterrupt:
        Color.pl('\n{!} {O}Interrupted, Shutting down...{W}')

if __name__ == '__main__':
    entry_point()
