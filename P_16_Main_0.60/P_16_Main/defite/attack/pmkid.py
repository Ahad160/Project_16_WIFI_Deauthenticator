#!/usr/bin/env python
# -*- coding: utf-8 -*-

from ..model.attack import Attack
from ..config import Configuration
from ..util.color import Color
from ..util.timer import Timer
from ..tools.airodump import Airodump
from threading import Thread
import os
import time
import re
from shutil import copy


class AttackPMKID(Attack):
    def __init__(self, target):
        super(AttackPMKID, self).__init__(target)
        self.crack_result = None
        self.do_airCRACK = False
        self.keep_capturing = None
        self.pcapng_file = Configuration.temp('pmkid.pcapng')
        self.success = False
        self.timer = None

    @staticmethod
    def get_existing_pmkid_file(bssid):
        """
        Load PMKID Hash from a previously-captured hash in ./hs/
        Returns:
            The hashcat hash (hash*bssid*station*essid) if found.
            None if not found.
        """
        if not os.path.exists(Configuration.wpa_handshake_dir):
            return None

        bssid = bssid.lower().replace(':', '')

        file_re = re.compile(r'.*pmkid_.*\.22000')
        for filename in os.listdir(Configuration.wpa_handshake_dir):
            pmkid_filename = os.path.join(Configuration.wpa_handshake_dir, filename)
            if not os.path.isfile(pmkid_filename):
                continue
            if not re.match(file_re, pmkid_filename):
                continue

            with open(pmkid_filename, 'r') as pmkid_handle:
                pmkid_hash = pmkid_handle.read().strip()
                if pmkid_hash.count('*') < 3:
                    continue
                existing_bssid = pmkid_hash.split('*')[1].lower().replace(':', '')
                if existing_bssid == bssid:
                    return pmkid_filename
        return None

    def run_hashcat(self):

        return True  # Even if we don't crack it, capturing a PMKID is 'successful'

    # TODO Rename this here and in `run_hashcat`
    def _extracted_from_run_hashcat_44(self, arg0):
        Color.pl(arg0)
        self.success = False
        return True

    def run(self):
        if self.do_airCRACK:
            self.run_aircrack()
        else:
            pass

    def run_aircrack(self):
        with Airodump(channel=self.target.channel,
                      target_bssid=self.target.bssid,
                      skip_wps=True,
                      output_file_prefix='wpa') as airodump:

            Color.clear_entire_line()
            Color.pattack('WPA', self.target, 'PMKID capture', 'Waiting for target to appear...')
            airodump_target = self.wait_for_target(airodump)

            timeout_timer = Timer(Configuration.wpa_attack_timeout)

            while not timeout_timer.ended():
                step_timer = Timer(1)
                Color.clear_entire_line()
                Color.pattack('WPA',
                              airodump_target,
                              'Handshake capture',
                              'Listening. (clients:{G}{W}, deauth:{O}{W}, timeout:{R}%s{W})' % timeout_timer)

                # Find .cap file
                cap_files = airodump.find_files(endswith='.cap')
                if len(cap_files) == 0:
                    # No cap files yet
                    time.sleep(step_timer.remaining())
                    continue
                cap_file = cap_files[0]

                # Copy .cap file to temp for consistency
                temp_file = Configuration.temp('handshake.cap.bak')
                copy(cap_file, temp_file)

                # Check cap file in temp for Handshake
                # bssid = airodump_target.bssid
                # essid = airodump_target.essid if airodump_target.essid_known else None

                # AttackPMKID.check_pmkid(temp_file, self.target.bssid)
                if self.check_pmkid(temp_file):
                    # We got a handshake
                    Color.clear_entire_line()
                    Color.pattack('WPA', airodump_target, 'PMKID capture', '{G}Captured PMKID{W}')
                    Color.pl('')
                    capture = temp_file
                    break

                # There is no handshake
                capture = None
                # Delete copied .cap file in temp to save space
                os.remove(temp_file)

                # # Sleep for at-most 1 second
                time.sleep(step_timer.remaining())
                # continue # Handshake listen+deauth loop

        if capture is None:
            # No handshake, attack failed.
            Color.pl('\n{!} {O}WPA handshake capture {R}FAILED:{O} Timed out after %d seconds' % (
                Configuration.wpa_attack_timeout))
            self.success = False
        else:
            # Save copy of handshake to ./hs/
            self.success = False
            self.save_pmkid(capture)

        return self.success

    def check_pmkid(self, filename):
        """Returns tuple (BSSID,None) if aircrack thinks self.capfile contains a handshake / can be cracked"""

        from ..util.process import Process

        command = f'aircrack-ng  "{filename}"'
        (stdout, stderr) = Process.call(command)

        return any('with PMKID' in line and self.target.bssid in line for line in stdout.split("\n"))

    def capture_pmkid(self):
        return True

    def crack_pmkid_file(self, pmkid_file):
  
        return False

    def _extracted_from_crack_pmkid_file_31(self, key, pmkid_file):
        return True

    def dumptool_thread(self):

        return True

    def save_pmkid(self, pmkid_hash):

        return True

    # TODO Rename this here and in `save_pmkid`
    def _extracted_from_save_pmkid_21(self, arg0):
        return True

    # TODO Rename this here and in `save_pmkid`
    def _extracted_from_save_pmkid_6(self, pmkid_hash):
        return True
