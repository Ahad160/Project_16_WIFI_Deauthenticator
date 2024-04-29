#!/usr/bin/env python
# -*- coding: utf-8 -*-

from .pmkid import AttackPMKID
from .wpa import AttackWPA
from ..config import Configuration
from ..model.target import WPSState
from ..util.color import Color


class AttackAll(object):
    @classmethod
    def attack_multiple(cls, targets):
        """
        Attacks all given `targets` (list[defite.model.target]) until user interruption.
        Returns: Number of targets that were attacked (int)
        """

        attacked_targets = 0
        targets_remaining = len(targets)
        for index, target in enumerate(targets, start=1):
            if Configuration.attack_max != 0 and index > Configuration.attack_max:
                print(("Attacked %d targets, stopping because of the --first flag" % Configuration.attack_max))
                break
            attacked_targets += 1
            targets_remaining -= 1

            bssid = target.bssid
            essid = target.essid if target.essid_known else '{O}ESSID unknown{W}'

            Color.pl('\n{+} ({G}%d{W}/{G}%d{W})'
                     % (index, len(targets)) + ' Starting attacks against {C}%s{W} ({C}%s{W})' % (bssid, essid))

            should_continue = cls.attack_single(target, targets_remaining)
            if not should_continue:
                break

        return attacked_targets

    @classmethod
    def attack_single(cls, target, targets_remaining):
        """
        Attacks a single `target` (defite.model.target).
        Returns: True if attacks should continue, False otherwise.
        """
        global attack
        if 'MGT' in target.authentication:
            Color.pl("\n{!}{O}Skipping. Target is using {C}WPA-Enterprise {O}and can not be cracked.")
            return True

        attacks = []

        if 'WPA' in target.encryption:

            if not Configuration.wps_only:
                # Handshake capture
                if not Configuration.use_pmkid_only:
                    attacks.append(AttackWPA(target))

        if not attacks:
            Color.pl('{!} {R}Error: {O}Unable to attack: no attacks available')
            return True  # Keep attacking other targets (skip)

        while attacks:
            # Needed by infinite attack mode in order to count how many targets were attacked
            target.attacked = True
            attack = attacks.pop(0)
            try:
                result = attack.run()
                if result:
                    break  # Attack was successful, stop other attacks.
            except Exception as e:
                # TODO:kimocoder: below is a great way to handle Exception
                # rather then running full traceback in run of parsing to console.
                Color.pl('\r {!} {R}Error{W}: %s' % str(e))
                #Color.pexception(e)         # This was the original one which parses full traceback
                #Color.pl('\n{!} {R}Exiting{W}\n')      # Another great one for other uasages.
                continue
            except KeyboardInterrupt:
                Color.pl('\n{!} {O}Interrupted{W}\n')
                answer = cls.user_wants_to_continue(targets_remaining, len(attacks))
                if answer is True:
                    continue  # Keep attacking the same target (continue)
                elif answer is None:
                    return True  # Keep attacking other targets (skip)
                else:
                    return False  # Stop all attacks (exit)


        return True  # Keep attacking other targets

    @classmethod
    def user_wants_to_continue(cls, targets_remaining, attacks_remaining=0):
        """
        Asks user if attacks should continue onto other targets
        Returns:
            None if the user wants to skip the current target
            True if the user wants to continue to the next attack on the current target
            False if the user wants to stop the remaining attacks
        """
        if attacks_remaining == 0 and targets_remaining == 0:
            return  # No targets or attacksleft, drop out

        prompt_list = []
        if attacks_remaining > 0:
            prompt_list.append(Color.s('{C}%d{W} attack(s)' % attacks_remaining))
        if targets_remaining > 0:
            prompt_list.append(Color.s('{C}%d{W} target(s)' % targets_remaining))
        prompt = ' and '.join(prompt_list) + ' remain'
        Color.pl('{+} %s' % prompt)

        prompt = '{+} Do you want to'
        options = '('

        if attacks_remaining > 0:
            prompt += ' {G}continue{W} attacking,'
            options += '{G}c{W}{D}, {W}'

        if targets_remaining > 0:
            prompt += ' {O}skip{W} to the next target,'
            options += '{O}s{W}{D}, {W}'

        if Configuration.infinite_mode:
            options += '{R}r{W})'
            prompt += ' or {R}return{W} to scanning %s? {C}' % options
        else:
            options += '{R}e{W})'
            prompt += ' or {R}exit{W} %s? {C}' % options

        Color.p(prompt)
        answer = input().lower()

        if answer.startswith('s'):
            return None  # Skip
        elif answer.startswith('e') or answer.startswith('r'):
            return False  # Exit/Return
        else:
            return True  # Continue
