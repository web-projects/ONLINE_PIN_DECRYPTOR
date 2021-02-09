#!/usr/bin/python3
'''
Created on 21-06-2012

@authors: Lucjan_B1, Kamil_P1, Matthew_H, Jon_B
'''

from testharness import *
from TC_testharness import *
import TC_testharness.utility as util
from functools import partial
from TC_testharness.tlvparser import TLVParser, tagStorage
from TC_testharness.tlvparser import TLVPrepare
from sys import exit
from testharness.syslog import getSyslog
from TC_testharness.syslog import getSyslog
from TC_testharness.utility import getch, kbhit
from testharness.utility import lrccalc
import testharness.fileops as fops
import TC_TCLink
import TC_TransactionHelper
from binascii import hexlify, unhexlify, b2a_hex
from time import sleep
import sys
import getpass
import datetime
import traceback
import os.path
from os import path
import re

# ---------------------------------------------------------------------------- #
# VERSION INFORMATION
#
# 20201208
# 1. Contactless multi-application selection: requires second tap
# 2. ONLINE PIN missing in transaction
# 3. BALANCE INQUIRY - set "--action", "verify" in launch.json
#VERSION_LBL = '1.0.0.0'
# 20201210
# 1. Paypass Purchase with cashback transaction
#    Changes to config files and TestHarness
VERSION_LBL = '1.0.0.1'
#
# ---------------------------------------------------------------------------- #

# ---------------------------------------------------------------------------- #
# GLOBALS
# ---------------------------------------------------------------------------- #

# TRANSACTION TYPE (TAG 9C)
# 0x00 - Sale / Purchase (EMV) - "transaction_type_goods" is used
# 0x01 - Cash Advance (EMV) - "transaction_type_cash" is used
# 0x09 - Sale / Purchase with cashback (EMV) - "transaction_type_goods_with_disbursement" is used
# 0x20 - Return / Refund (EMV) - "transaction_type_returns" is used
# 0x30 - Balance (non-EMV) - "transaction_type_balance_inquiry" is used
# 0x31 - Reservation (non-EMV) - "transaction_type_reservation" is used
# 0xFE - none (non-EMV) - "transaction_type_" is skipped

TRANSACTION_TYPE = b'\x00'  # SALE TRANSACTION
#TRANSACTION_TYPE = b'\x09'  # SALE WITH CASHBACK TRANSACTION - MTIP05-USM Test 08 Scenario 01f
# BALANCE INQUIRY - MTIP06_10_01_15A, MTIP06_12_01_15A
ISBALANCEINQUIRY = TRANSACTION_TYPE == b'\x30'
AMOUNTFORINQUIRY = b'\x00\x00\x00\x00\x00\x00'

# UX == UNATTENDED
DEVICE_UNATTENDED = ""

EMV_CARD_REMOVED = 0
EMV_CARD_INSERTED = 1
MAGSTRIPE_TRACKS_AVAILABLE = 2
ERROR_UNKNOWN_CARD = 3

QUICKCHIP_ENABLED = [(0xDF, 0xCC, 0x79), [0x01]]
ISSUER_AUTH_DATA = [(0x91), [0x37, 0xDD, 0x29, 0x75, 0xC2, 0xB6, 0x68, 0x2D, 0x00, 0x12]]

# iccdata.dat: #65
ACQUIRER_ID = [(0xC2), [0x36, 0x35]]

###
# DNA COMBINATION TO OBTAIN 2nd GENERATE ACC:
#   1. AUTHRESPONSECODE = Z3
#   2. ONLINE ACTION REQUIRED TEMPLATE 0xE4 MUST HAVE args.online == "y"
###

# AUTHRESPONSECODE = [ (0x8A), [0x30, 0x30] ]  # authorization response code of 00
# AUTHRESPONSECODE = [ (0x8A), [0x59, 0x31] ]  # authorization response code of Y1
# AUTHRESPONSECODE = [ (0x8A), [0x59, 0x32] ]  # authorization response code of Y2
AUTHRESPONSECODE = [(0x8A), [0x5A, 0x33]]      # authorization response code of Z3 (unable to contact host)

# CURRENCY / COUNTRY CODE
UK = b'\x08\x26'
US = b'\x08\x40'
CH = b'\x01\x56'
CURRENCY_CODE = [(0x5F, 0x2A), US]
COUNTRY_CODE = [(0x9F, 0x1A), US]

# After an AAR (Application Authorisation Referral) or ARQC (Authorisation Request Cryptogram) where the acquirer
# is contacted, the decision is made with tag C0. If the acquirer cannot be contacted or a stand-in authorisation
# is detected, do not send this tag. By not sending the tag, default analysis is carried out.
#
# ‘C0’ must be sent in the next ‘Continue Transaction’ command, set as positive to request a TC or negative to request an AAC.
CONTINUE_REQUEST_TC  = [(0xC0), [0x00]]  # Offline (Z3)
CONTINUE_REQUEST_AAC = [(0xC0), [0x01]]  # Online (00)

ONLINE = 'n'
ISOFFLINE = AUTHRESPONSECODE[1] == [0x5A, 0x33]

# BCD EMV values (must poplate before transaction start)
AMOUNT = b'\x00\x00\x00\x00\x01\x00'
AMTOTHER = b'\x00\x00\x00\x00\x00\x00'
DATE = b'\x20\x10\x01'
TIME = b'\x00\x00\x00'

APPLICATION_LABEL = ''

# ONLINE PIN LENGTHS
PINLEN_MIN = 0x04
PINLEN_MAX = 0x06

OnlineEncryptedPIN = ""
OnlinePinKSN = ""
OnlinePinContinueTPL = []
OFFLINERESPONSE = ""

# DISPLAY MESSAGES
DM_9F25 = "BAD CARD-TRANSACTION ABORTED"
DM_9F28 = "CARD NOT SUPPORTED"
DM_9F31 = "PLEASE PRESENT ONE CARD ONLY"
DM_9F33 = "SEE PHONE FOR INSTRUCTIONS"
DM_9F34 = "INSERT CARD"
DM_9F35 = "ENTER CONSUMER DEVICE CVM"
DM_9F41 = "USER CANCELLED PIN ENTRY"
DM_9F42 = "CASHBACK NOT ALLOWED"

# PROCESSING
EMV_VERIFICATION = 0

# FINAL ACTIONS
SIGN_RECEIPT = False

# EMV TO MSR FALLBACK
FALLBACK_TYPE = 'technical'

LIST_STYLE_SCROLL = 0x00
LIST_STYLE_NUMERIC = 0x01
LIST_STYLE_SCROLL_CIRCULAR = 0x02

# ---------------------------------------------------------------------------- #
# UTILTIES
# ---------------------------------------------------------------------------- #

def AbortTransaction():
    log.logerr('Abort Current Transaction')
    conn.send([0xD0, 0xFF, 0x00, 0x00])
    status, buf, uns = getAnswer()
    return -1


def ResetDevice():
    # Send reset device
    # P1 - 0x00
    # perform soft-reset, clears all internal EMV collection data and returns Terminal ID,
    #  Serial Number and Application information
    conn.send([0xD0, 0x00, 0x00, 0x01])
    status, buf, uns = getAnswer()
    log.log('Device reset')
    return buf


# Finalise the script, clear the screen
def performCleanup():
    # DISPLAY [D2 01]
    conn.send([0xD2, 0x01, 0x01, 0x00])
    log.log('*** RESET DISPLAY ***')
    status, buf, uns = getAnswer(True, False)
    # Disconnect


def vsdSREDTemplateDebugger(tlv, tid):
    #print(">>> ff7f", tlv.tagCount((0xFF,0x7F)))
    if tlv.tagCount((0xFF, 0x7F)):
        #log.log('>>> vsp_tlv bytes', tlv.getTag((0xFF,0x7F))[0])
        tlvp = TLVPrepare()
        vsp_tlv_tags = tlvp.parse_received_data(tlv.getTag((0xFF, 0x7F))[0])
        vsp_tlv = TLVParser(vsp_tlv_tags)
        #vsp_tlv = TLVParser(tlv.getTag((0xFF,0x7F))[0])
        #log.log('>>> buf', buf)
        #log.log('>>> tlv', tlv)
        #log.log('>>> vsp_tlv_tags', vsp_tlv_tags)
        #log.log('>>> vsp_tlv', vsp_tlv)
        if vsp_tlv.tagCount((0xDF, 0xDF, 0x10)):
            print(">>> vsp_tlv DFDF10", hexlify(vsp_tlv.getTag((0xDF, 0xDF, 0x10))[0]))
        if vsp_tlv.tagCount((0xDF, 0xDF, 0x11)):
            print(">>> vsp_tlv DFDF11", hexlify(vsp_tlv.getTag((0xDF, 0xDF, 0x11))[0]))
        if vsp_tlv.tagCount((0xDF, 0xDF, 0x12)):
            print(">>> vsp_tlv DFDF12", hexlify(vsp_tlv.getTag((0xDF, 0xDF, 0x12))[0]))
        if vsp_tlv.tagCount((0xDF, 0xDF, 0x10)) and vsp_tlv.tagCount((0xDF, 0xDF, 0x11)) and vsp_tlv.tagCount((0xDF, 0xDF, 0x12)):
            encryptedtrack = 'TVP|iv:' + vsp_tlv.getTag((0xDF, 0xDF, 0x12))[0].hex() + '|ksn:' + vsp_tlv.getTag(
                (0xDF, 0xDF, 0x11))[0].hex() + '|vipa:' + vsp_tlv.getTag((0xDF, 0xDF, 0x10))[0].hex()
            log.log('>>> encryptedtrack=' + str(encryptedtrack) + '\\ncustid=' + str(args.custid) +
                    '\\npassword=' + str(args.password) + '\\naction=' + str(args.action) + '\\ndevice_serial=' + str(tid))


def reportTerminalCapabilities(tlv):
    if tlv.tagCount((0x9F, 0x33)):
        termCaps = tlv.getTag((0x9F, 0x33))
        if (len(termCaps)):
            log.logwarning("TERMINAL CAPABILITIES:", hexlify(termCaps[0]).decode('ascii'))


# Gets answer from the device, optionally ignoring unsolicited and stopping on errors
def getAnswer(ignoreUnsolicited=True, stopOnErrors=True):
    while True:
        status, buf, uns = conn.receive()
        if uns and ignoreUnsolicited:
            log.log('Unsolicited packet detected: ', TLVParser(buf))
            continue
        #
        # track acceptable errors in EMV Certification Testing
        #
        if status != 0x9000 and status != 0x9F36 and status != 0x9f22 and status != 0x9f25 and status != 0x9f28 and status != 0x9f31 and status != 0x9f33 and status != 0x9f34 and status != 0x9f35 and status != 0x9f41 and status != 0x9f42:
            log.logerr('Pinpad reported error ', hex(status))
            traceback.print_stack()
            if stopOnErrors:
                performCleanup()
                exit(-1)
        break
    return status, buf, uns


def getEMVAnswer(ignoreUnsolicited=False):
    return getAnswer(ignoreUnsolicited, False)


# ---------------------------------------------------------------------------- #
# DEVICE CONNECTIVITY AND STATE
# ---------------------------------------------------------------------------- #

def startMonitoringCardStatus():
    log.log('*** START CARD MONITORING ***')
    ### ------------------------------------------------------------------------------------------
    # Clarifications added to VIPA manual in version 6.8.2.11.
    # When the ICC notification is disabled (i.e. P1 bit 7) then VIPA will not be able to send
    # unsolicited response for the changes in card status. However for MSR transaction in UX30x,
    # POS can simply disable ATR notification (i.e. P1 bit 1) and VIPA will notify the POS
    # regarding the card insertion and POS can fallback to magstripe.
    ### ------------------------------------------------------------------------------------------
    # P1 - REQUESTS
    # Bit 7 - Disables ICC notifications
    # Bit 6 - Disables magnetic reader notifications
    # Bit 5 - Enables magnetic track status reporting (tag DFDF6E)
    # Bit 4 - Requests the Track 3 data in the response (tag 5F23)
    # Bit 3 - Requests the Track 2 data in the response (tag 5F22)
    # Bit 2 - Requests the Track 1 data in the response (tag 5F21)
    # Bit 1 - Requests the ATR in the response (tag 63)
    # Bit 0 - Sets the device to report changes in card status
    #
    P1 = 0x3F
    # P2 - Monitor card and keyboard status
    # 00 - stop reporting key presses
    # Bit 1 - report function key presses
    # Bit 0 - report enter, cancel and clear key presses
    ## ICC + MSR
    P2 = 0x03
    #
    # CARD STATUS [D0, 60]
    conn.send([0xD0, 0x60, P1, P2])


def stopMonitoringCardStatus():
    log.log('*** STOP CARD MONITORING ***')
    ## CARD STATUS [D0, 60]
    conn.send([0xD0, 0x60, 0x00, 0x00])
    status, buf, uns = getAnswer(False)


def stopMonitoringKeyPresses():
    # STOP Monitor card and keyboard status
    # P2 - keyboard monitoring
    # 00 - stop reporting key presses
    # Bit 0 - report enter, cancel and clear key presses
    # Bit 1 - report function key presses
    conn.send([0xD0, 0x61, 0x00, 0x00])
    log.log('*** STOP KEYBOARD MONITORING ***')
    status, buf, uns = getAnswer(False)
 
 
# ---------------------------------------------------------------------------- #
# TRANSACTION PROCESSING
# ---------------------------------------------------------------------------- #

def displayMsg(message, pause=0):
    # DISPLAY [D2, 01]
    conn.send([0xD2, 0x01, 0x00, 0x01], '\x0D\x09'+message)
    status, buf, uns = getAnswer()
    if pause > 0:
        sleep(pause)


def processNoCashbackAllowed(tlv, tid):
    # expects 1st GENERATE AAC
    continue_tpl = sendFirstGenAC(tlv, tid)
    status, buf, uns = getEMVAnswer()
    # expects 2nd GENERATE AAC
    if status == 0x9000:
        sendSecondGenAC(continue_tpl)


def displayAidChoice(tlv):
    ''' Retrieve application list '''
    appLabels = tlv.getTag(0x50)
    appAIDs = tlv.getTag((0x9F, 0x06))
    appPriority = tlv.getTag((0x87))
    log.log('We have ', len(appLabels), ' applications')

    app_sel_tags = []

    for i in range(len(appLabels)):
        app_sel_tags.append([(0x50), appLabels[i]])
        app_sel_tags.append([(0x87), appPriority[i]])
        app_sel_tags.append([(0x9F, 0x06), appAIDs[i]])

    app_sel_templ = (0xE0, app_sel_tags)
    log.log("CONTINUE TRANSACTION: AID CHOICE ---------------------------------------------------------------------")
    # CONTINUE TRANSACTION [DE D2]
    conn.send([0xDE, 0xD2, 0x00, 0x00], app_sel_templ)
    log.log('waiting for App Selection...')
    status, buf, uns = getEMVAnswer()
    if status != 0x9000:
        return -1


def requestAIDChoice(tlv):
    ''' Retrieve application list '''
    appLabels = tlv.getTag(0x50)
    appAIDs = tlv.getTag((0x9F, 0x06))
    log.log('We have ', len(appLabels), ' applications:')

    if len(appLabels) != len(appAIDs):
        log.logerr('Invalid response: AID count ', len(appAIDs), ' differs from Labels count ', len(appLabels))
        exit(-1)

    ''' Set selection list '''
    c_tag = tagStorage()
    c_tag.store((0xDF, 0xA2, 0x12), LIST_STYLE_SCROLL)

    # BUG: Unable to push the direct string not bytearray
    c_tag.store((0xDF, 0xA2, 0x11), 'SELECT AN APPLICATION')
    for i in range(len(appLabels)):
        log.log('App ', i+1, ': AID ', hexlify(appAIDs[i]), ', label ', str(appLabels[i]))
        c_tag.store((0xDF, 0xA2, 0x02), i)
        c_tag.store((0xDF, 0xA2, 0x03), str(appLabels[i]))

    ''' Send request '''
    conn.send([0xD2, 0x03, 0x00, 0x01], c_tag.get())

    status, buf, uns = getEMVAnswer()
    if status != 0x9000:
        return -1

    tlv = TLVParser(buf)
    if tlv.tagCount((0xDF, 0xA2, 0x02)) == 1:
        selection = tlv.getTag((0xDF, 0xA2, 0x02))[0]
        #TC_transtest_all_autoselect_EMV.log.log("USER SELECTED:", selection[0])
        if selection >= 0:
            selection = selection - 1
            log.log('Selected ', selection)
            app_sel_tags = [
                [(0x50), bytearray(appLabels[selection])],
                [(0x9F, 0x06), bytearray(appAIDs[selection])],
                ACQUIRER_ID
            ]
            app_sel_templ = (0xE0, app_sel_tags)
			
            log.log("CONTINUE TRANSACTION: AID CHOICE ---------------------------------------------------------------------")
            # CONTINUE TRANSACTION [DE D2]
            conn.send([0xDE, 0xD2, 0x00, 0x00], app_sel_templ)
            log.log('App selected, waiting for response...')


def applicationSelection(tlv):
    # This is app selection
    appLabels = tlv.getTag(0x50)
    appAIDs = tlv.getTag((0x9F, 0x06))
    log.log('We have ', len(appLabels), ' applications')

    if len(appLabels) != len(appAIDs):
        log.logerr('Invalid response: AID count ', len(appAIDs), ' differs from Labels count ', len(appLabels))
        exit(-1)

    for i in range(len(appLabels)):
        log.log('App ', i+1, ': AID ', hexlify(appAIDs[i]), ', label ', str(appLabels[i]))

    sel = -1

    while True:
        # Note: The below will work for up to 9 apps...
        if kbhit():
            try:
                sel = ord(getch())
            except:
                print('invalid key!')
            #TC_transtest_all_autoselect_EMV.log.log('key press ', sel)
            if sel > 0x30 and sel <= 0x30+len(appLabels):
                sel -= 0x30  # to number (0 .. x)
                break
            elif sel == 27:
                # ABORT [D0 FF]
                return AbortTransaction()

            print(' Invalid selection, please pick valid number! ')

        if conn.is_data_avail():
            status, buf, uns = getEMVAnswer()
            if status != 0x9000:
                log.logerr('Transaction terminated with status ', hex(status))
                return -1
            break

    # user made a selection
    if sel >= 0:
        sel = sel - 1
        log.log('Selected ', sel)
        app_sel_tags = [
            [(0x50), bytearray(appLabels[sel])],
            [(0x9F, 0x06), bytearray(appAIDs[sel])],
            ACQUIRER_ID
        ]
        app_sel_templ = (0xE0, app_sel_tags)
        log.log("CONTINUE TRANSACTION: AID CHOICE ---------------------------------------------------------------------")
        # CONTINUE TRANSACTION [DE D2]
        conn.send([0xDE, 0xD2, 0x00, 0x00], app_sel_templ)
        log.log('App selected, waiting for response...')


# Checks card status, based on device response
def EMVCardState(tlv):
    res = -1
    # Check for card status
    if tlv.tagCount(0x48):
        ins_tag_val = tlv.getTag(0x48, TLVParser.CONVERT_INT)[0]
        # Byte 0
        ins_tag_val &= 0xFF00
        ins_tag_val >>= 8
        if ins_tag_val == 3:
            log.log('Card inserted!')
            res = EMV_CARD_INSERTED
        else:
            if ins_tag_val == 0:
                res = EMV_CARD_REMOVED
            else:
                res = ERROR_UNKNOWN_CARD
    return res


# Checks card status, based on device response
def CardIsEMVCapable(tlv):
    res = False
    # Check for card status
    if tlv.tagCount(0x48):
        ins_tag_val = tlv.getTag(0x48, TLVParser.CONVERT_INT)[0]
        # Byte 1
        # Bit 1: Track 1 available
        ins_tag_val &= 0x0002
        if ins_tag_val != 2:
            serviceCode = getMSRTrack2ServiceCode(tlv)
            if serviceCode[0] == '2':
                log.log('Card is EMV Capable')
                res = True
    return res


# Get magstripe status, based on device response
def MagstripeCardState(tlv):
    res = -1
    # Check for card status
    if tlv.tagCount(0x48):
        ins_tag_val = tlv.getTag(0x48, TLVParser.CONVERT_INT)[0]
        ins_tag_val &= 0x00FF
        if ins_tag_val == 1:
            log.logerr('Magstripe, but no tracks!')
            res = ERROR_UNKNOWN_CARD
        else:
            if ins_tag_val == 0:
                res = EMV_CARD_REMOVED
            else:
                res = MAGSTRIPE_TRACKS_AVAILABLE
    return res


# Ask for card removal and waits until card is removed
def removeEMVCard():
    # DISPLAY [D2 01]
    conn.send([0xD2, 0x01, 0x0E, 0x01])
    status, buf, uns = getAnswer(False)
    if status != 0x9000:
        log.logerr('Remove card', hex(status), buf)
        exit(-1)
    log.log('*** REMOVE CARD WAIT ***')
    tlv = ''
    while True:
        status, buf, uns = getAnswer(False)
        if uns:
            tlv = TLVParser(buf)
            cardState = EMVCardState(tlv)
            if cardState == EMV_CARD_REMOVED:
                break
        if len(tlv):
            log.logerr('Bad packet ', tlv)

    return tlv

        
# Processes magstripe fallback - asks for swipe
def processMagstripeFallback(tid):
    global FALLBACK_TYPE
    # Ask for removal and swipe
    # CARD STATUS [D0 60]
    # P1
    # Bit 7 - Disables ICC Notifications
    # Bit 6 - Disables MSR track reporting
    # Bit 5 - Enables MSR track reporting
    # Bit 4 - Requests Track 3 data in response
    # Bit 3 - Requests Track 2 data in response
    # Bit 2 - Requests Track 1 data in response
    # Bit 1 - Request the ATR in response
    # P1 = 0x1F - ALLOW ALL NOTIFICATIONS
    conn.send([0xD0, 0x60, 0x1F, 0x00])
    while True:
        status, buf, uns = getAnswer(False)  # Get unsolicited
        if uns:
            tlv = TLVParser(buf)
            cardStatus = EMVCardState(tlv)
            if cardStatus == EMV_CARD_INSERTED or cardStatus == ERROR_UNKNOWN_CARD:
                tlv = removeEMVCard()
            break

    # Cancel Contactless first
    cancelContactless()

    # Ask for swipe
    if MagstripeCardState(tlv) == EMV_CARD_REMOVED:
        promptForSwipeCard()
        # Wait for swipe
        while True:
            status, buf, uns = getAnswer(False)
            if uns:
                tlv = TLVParser(buf)
                magState = MagstripeCardState(tlv)
                if magState == ERROR_UNKNOWN_CARD or magState == MAGSTRIPE_TRACKS_AVAILABLE:
                    break
            log.log('Ignoring unsolicited packet ', tlv)
            continue
    if MagstripeCardState(tlv) == MAGSTRIPE_TRACKS_AVAILABLE:
        TC_TransactionHelper.vspDecrypt(tlv, tid, log)
        TC_TCLink.saveCardData(tlv)
        TC_TCLink.setDeviceFallbackMode(FALLBACK_TYPE)
    # We're done!
    return 5


# Contactless multi-application selection - requires a second tap
def requestChoice(message, length):
    choice = -1
    # CHOICE [D2 03]
    command = '02001ad2030000'
    data = length + message
    command += data
    # LRC is in the entire command string
    lrcdata = bytes.fromhex(command)
    lrc = lrccalc(lrcdata)
    command += hex(lrc)[2:]
    log.log("DATA:" + command)

    # stop card monitoring
    # stopMonitoringCardStatus()

    # send command to device
    conn.send_rawhex(command)
    status, buf, uns = getAnswer(False)

    if status == 0x9000:
        tlv = TLVParser(buf)
        if tlv.tagCount((0xDF, 0xAA, 0x01)):
            choice = tlv.getTag((0xDF, 0xAA, 0x01))[0]
    return choice


# ---------------------------------------------------------------------------- #
# PIN Workflow
# ---------------------------------------------------------------------------- #

def verifyOfflinePIN(pinTryCounter):
    global AMOUNT, APPLICATION_LABEL

    pinoffline_verify_tag = [
        APPLICATION_LABEL, 
		CURRENCY_CODE, 
		[ (0x9F, 0x02), AMOUNT],        # transaction amount
        [(0x5F, 0x36), [0x02]],         # currency exponent
        #[ (0x9F, 0x2E), [] ],          # ICC PIN Encipherment Public Key Exponent
        #[ (0x9F, 0x47), [0x03] ],      # ICC Public Key Exponent
        [(0x9F, 0x17), pinTryCounter]   # PIN Try Counter
    ]
    pinoffline_tpl = (0xE0, pinoffline_verify_tag)

    conn.send([0xDE, 0xD5, 0x01, 0x00], pinoffline_tpl)
    status, buf, uns = getAnswer(stopOnErrors=False)
    log.logerr('PIN VERIFY RESULT:', buf[0].hex())


def getOnlinePin(tlv):
    global TRANSACTION_TYPE, AMOUNT, PINLEN_MIN, PINLEN_MAX

    onlinepin_tag = [
        [(0xDF, 0xDF, 0x17), AMOUNT],          # transaction amount
        [(0xDF, 0xDF, 0x24), b'PLN'],          # transaction currency
        # transaction currency exponent
        # transaction type
        # pin entry timeout: default 30 seconds
        # min pin length
        # max pin length
        # 20201119: JIRA TICKET VS-52542 as this option does not work
        # AXP QC 037 - ALLOW PIN BYPASS WITH <GREEN> BUTTON
        # PIN entry type: pressing ENTER on PIN Entry screen (without any PIN digits) will return SW1SW2=9000 response with no data
        [(0xDF, 0xDF, 0x1C), 0x02], 
        [(0xDF, 0xDF, 0x1D), TRANSACTION_TYPE], 
        [(0xDF, 0xA2, 0x0E), 0x0F], [(0xDF, 0xED, 0x04), PINLEN_MIN], 
        [(0xDF, 0xED, 0x05), PINLEN_MAX], 
        [(0xDF, 0xEC, 0x7D), b'0x01']
    ]
    onlinepin_tpl = (0xE0, onlinepin_tag)

    # Alter from default of 2 to VSS Script index 2 (host_id=3)
    host_id = 0x02

    # ONLINE PIN [DE, D6]
    conn.send([0xDE, 0xD6, host_id, 0x00], onlinepin_tpl)
    status, buf, uns = getEMVAnswer()

    if status == 0x9000:
        pin_tlv = TLVParser(buf)

        # PIN bypass is allowed as per: AXP QC 037
        encryptedPIN = pin_tlv.getTag((0xDF, 0xED, 0x6C))
        if len(encryptedPIN):
            encryptedPIN = pin_tlv.getTag((0xDF, 0xED, 0x6C))[0].hex().upper()
            if len(encryptedPIN):
                ksn = pin_tlv.getTag((0xDF, 0xED, 0x03), TLVParser.CONVERT_HEX_STR)[0].upper()
                if len(ksn):
                    displayMsg('Processing ...')
                    TC_TCLink.saveEMVData(tlv, 0xE4)


def performUserPINEntry():

    log.log('PIN Entry is being performed, waiting again')
    print('PIN Entry, press \'A\' to abort, \'B\' to bypass or \'C\' to cancel')

    while True:
        #sleep(1)
        validKey = False

        if kbhit():
            key = getch()
            log.log('key press ', key)

            if key == 'a' or key == 'A':
                log.logerr('aborting')
                # ABORT [D0 FF]
                conn.send([0xD0, 0xFF, 0x00, 0x00])
                validKey = True

            if key == 'b' or key == 'B':
                log.logerr('bypassing')
                # VERIFY PIN [DE D5]
                conn.send([0xDE, 0xD5, 0xFF, 0x01])
                validKey = True

            if key == 'c' or key == 'C':
                log.logerr('cancelling')
                # VERIFY PIN [DE D5]
                conn.send([0xDE, 0xD5, 0x00, 0x00])
                validKey = True

            if validKey:
                # Wait for confirmation, then break to wait for response
                status, buf, uns = getAnswer(stopOnErrors=False)
                if status == 0x9000:
                    break
                else:
                    continue
            else:
                continue

        if conn.is_data_avail():
            break


def getPINEntry(tlv):

    global OnlineEncryptedPIN, OnlinePinKSN

    log.log('PIN Entry is being performed, waiting again')
    #PANDATA = b'\x54\x13\x33\x00\x89\x00\x00\x39'
    #log.log("PAN: ", hexlify(PANDATA).decode('ascii'))
    onlinepin_tag = [
        [(0xDF, 0xDF, 0x17), AMOUNT],   # transaction amount
        [(0xDF, 0xDF, 0x24), b'PLN'],   # transaction currency
        [(0xDF, 0xDF, 0x1C), 0x02],     # transaction currency exponent
        [(0xDF, 0xA2, 0x0E), 0x0F],     # pin entry timeout: default 30 seconds
        #[(0x5A), PANDATA]               # PAN DATA
    ]
    #response = "declined"
    #attempts = 0
    # while response != "approved" and attempts < args.pinattempts:
    onlinepin_tpl = (0xE0, onlinepin_tag)
    # ONLINE PIN [DE, D6]
    conn.send([0xDE, 0xD6, 0x02, 0x00], onlinepin_tpl)
    status, buf, uns = getEMVAnswer()
    if status != 0x9000:
        return -1
    pin_tlv = TLVParser(buf)
    displayMsg('Processing')

    OnlineEncryptedPIN = pin_tlv.getTag((0xDF, 0xED, 0x6C))[0].hex().upper()
    OnlinePinKSN = pin_tlv.getTag((0xDF, 0xED, 0x03), TLVParser.CONVERT_HEX_STR)[0].upper()

    return 1


def OnlinePinTransaction(tlv, cardState, continue_tpl, need2ndGen=True, setattempts = 0):
    global TRANSACTION_TYPE, AMOUNT, PINLEN_MIN, PINLEN_MAX

    # AXP QC 032 REQUIRES 2nd GENERATE AC to report TAGS 8A and 9F27
    if need2ndGen:
        sendSecondGenAC(continue_tpl)

    log.log('Online PIN mode')

    # If SRED is enabled and pan_cache_timeout is specified in the [vipa] section of MAPP_VSD_SRED.CFG, the last cached PAN will be used for
    # PIN Block Formats that require PAN in case the PAN tag is not supplied.
    #PANDATA = b'\x54\x13\x33\x00\x89\x00\x00\x39'
    #PANDATA = tlv.getTag(0x5A)
    #log.log("PAN: ", hexlify(PANDATA).decode('ascii'))

    onlinepin_tag = [
        [(0xDF, 0xDF, 0x17), AMOUNT],          # transaction amount
        [(0xDF, 0xDF, 0x24), b'PLN'],          # transaction currency
        # transaction currency exponent
        # transaction type
        # pin entry timeout: default 30 seconds
        # min pin length
        # max pin length
        # [(0x5A), PANDATA],                     # PAN DATA
        [(0xDF, 0xDF, 0x1C), 0x02], 
        [(0xDF, 0xDF, 0x1D), TRANSACTION_TYPE], 
        [(0xDF, 0xA2, 0x0E), 0x0F], 
        [(0xDF, 0xED, 0x04), PINLEN_MIN], 
        [(0xDF, 0xED, 0x05), PINLEN_MAX], 
        # 20201119: JIRA TICKET VS-52542 as this option does not work
        # AXP QC 037 - ALLOW PIN BYPASS WITH <GREEN> BUTTON
        # PIN entry type: pressing ENTER on PIN Entry screen (without any PIN digits) will return SW1SW2=9000 response with no data
        [(0xDF, 0xEC, 0x7D), b'\x01']
    ]
    onlinepin_tpl = (0xE0, onlinepin_tag)

    response = "declined"
    attempts = setattempts
    host_id = 0x02  # Alter from default of 2 to VSS Script index 2 (host_id=3)

    while response != "approved" and attempts < args.pinattempts:
        # ONLINE PIN [DE, D6]
        conn.send([0xDE, 0xD6, host_id, 0x00], onlinepin_tpl)
        status, buf, uns = getEMVAnswer()
        if status != 0x9000:
            break
        pin_tlv = TLVParser(buf)

        # PIN bypass is allowed as per: AXP QC 037
        encryptedPIN = pin_tlv.getTag((0xDF, 0xED, 0x6C))
        if len(encryptedPIN):
            encryptedPIN = pin_tlv.getTag((0xDF, 0xED, 0x6C))[0].hex().upper()
            if len(encryptedPIN):
                ksn = pin_tlv.getTag((0xDF, 0xED, 0x03), TLVParser.CONVERT_HEX_STR)[0].upper()
                if len(ksn):
                    displayMsg('Processing ...')
                    TC_TCLink.saveEMVData(tlv, 0xE4)

                    # send to process online PIN entry
                    response = TC_TCLink.processPINTransaction(encryptedPIN, ksn)
                    log.log("PIN response: " + response)
                    if response != "approved":
                        displayMsg('Invalid PIN', 3)
                        attempts += 1

                    TC_TCLink.SetProperties(args, log)

                    if response != "approved" and attempts >= args.pinattempts:
                        displayMsg('PIN try limit exceeded', 3)
        else:
            # force PIN bypass
            status = 0x9f41
            break

    # user pinbypass
    nextstep = -1
    if status == 0x9f41:
        nextstep = 2
        processPinBypass()

    if (cardState == EMV_CARD_INSERTED):
        removeEMVCard()

    # transaction result
    if nextstep == -1:
        displayMsg(response.upper(), 3)

        # DISPLAY [D2, 01]
        conn.send([0xD2, 0x01, 0x01, 0x01])
        log.log("Online PIN transaction:", response)
        sleep(2)

    # DISPLAY [D2 01]
    conn.send([0xD2, 0x01, 0x01, 0x00])
    log.log('*** RESET DISPLAY ***')
    status, buf, uns = getAnswer()

    return nextstep


def OnlinePinInTemplateE6(tlv, cardState, continue_tpl):
    global TRANSACTION_TYPE, AMOUNT, PINLEN_MIN, PINLEN_MAX
    global OnlineEncryptedPIN, OnlinePinKSN
 
    # If SRED is enabled and pan_cache_timeout is specified in the [vipa] section
    # of MAPP_VSD_SRED.CFG, the last cached PAN will be used for PIN Block
    # Formats that require PAN in case the PAN tag is not supplied.
    #PANDATA = b'\x54\x13\x33\x00\x89\x00\x00\x39'

    # DFED0D
    # Flags for the entry. The following bits are checked:
    # • Bit 0 = bypass KSN incrementation in case of DUKPT support
    # • Bit 4 = PIN confirmation request: PINblock is not returned, check Return code (DFDF30) for PIN confirmation result
    # • Bit 5 = use Flexi PIN entry method (see information on Flexi PIN entry below) - only VOS and VOS2 platforms
    # • Bit 6 = PIN already entered, only processing request
    # • Bit 7 = PIN collected, no further processing required
    retrieve_pinblock = b'\x40'
    #
    # ONLINE_PIN_PART_OF_EMV_TRANS=1 must be set in cardapp.cfg
    #
    onlinepin_tag = [
        #[(0x5A), PANDATA],
        [(0xDF, 0xED, 0x0D), retrieve_pinblock]
    ]
    onlinepin_tpl = (0xE0, onlinepin_tag)

    # Alter from default of 2 to VSS Script index 2 (host_id=3)
    host_id = 0x02

    # ONLINE PIN [DE, D6]
    log.log('Online PIN: retrieving PINBLOCK ------------------------------------------------------------------------')
    conn.send([0xDE, 0xD6, host_id, 0x00], onlinepin_tpl)
    status, buf, uns = getEMVAnswer()
    if status != 0x9000:
        return -1
    pin_tlv = TLVParser(buf)

    # obtain PIN Block: KSN and Encrypted data
    encryptedPIN = pin_tlv.getTag((0xDF, 0xED, 0x6C))
    if len(encryptedPIN):
        encryptedPIN = pin_tlv.getTag((0xDF, 0xED, 0x6C))[0].hex().upper()
        if len(encryptedPIN):
            OnlineEncryptedPIN = encryptedPIN
            ksn = pin_tlv.getTag((0xDF, 0xED, 0x03), TLVParser.CONVERT_HEX_STR)[0].upper()
            if len(ksn):
                OnlinePinKSN = ksn
                displayMsg('Processing ...')
                TC_TCLink.saveEMVData(tlv, 0xE4)
                
    # send transaction online
    return 6


def processPinBypass():
    log.log("USER REQUESTED PIN BYPASS -------------------------------")
    # indicate PIN bypass
    #conn.send([0xDE, 0xD5, 0xFF, 0x00])
    #status, buf, uns = getAnswer(stopOnErrors = False)

    # cancel active PIN verification process because of PIN bypass request
    # if status == 0x9000:
    pinbypass_tag = [
        [(0xC3), [0x0E]]  # PIN Entry bypassed
    ]
    pinbypass_tpl = (0xE0, pinbypass_tag)
    
    log.log("CONTINUE TRANSACTION: GenAC1 -----------------------------------------------------------------------------")
    
    conn.send([0xDE, 0xD2, 0x00, 0x00], pinbypass_tpl)
    status, buf, uns = getAnswer(stopOnErrors=False)


def getOnlinePIN(tlv):
    global OnlineEncryptedPIN, OnlinePinKSN
    if tlv.tagCount((0xFF, 0x7F)):
        sRED = tlv.getTag((0xFF, 0x7F), TLVParser.CONVERT_HEX_STR)[0].upper()
        if len(sRED):
            #log.log("SRED DATA: " + sRED)
            # Encrypted PIN
            encryptedDataIndex = sRED.find('DFDF10')
            if encryptedDataIndex != -1:
                dataLen = int(sRED[encryptedDataIndex+6:encryptedDataIndex+8], 16) * 2
                OnlineEncryptedPIN = sRED[encryptedDataIndex+8:encryptedDataIndex+8+dataLen]
                # KSN
                ksnIndex = sRED.find('DFDF11')
                if ksnIndex != -1:
                    dataLen = int(sRED[ksnIndex+6:ksnIndex+8], 16) * 2
                    OnlinePinKSN = sRED[ksnIndex+8:ksnIndex+8+dataLen]
                    #log.log("OnlineEncryptedPIN: " + OnlineEncryptedPIN)
                    #log.log("OnlinePinKSN _____: " + OnlinePinKSN)
                    return True
        return False


def processOnlinePIN(tlv, cardState, continue_tpl):
    # abort transaction
    AbortTransaction()
    # Online PIN
    return OnlinePinTransaction(tlv, cardState, continue_tpl, False)

# ---------------------------------------------------------------------------- #
# MSR Workflow
# ---------------------------------------------------------------------------- #

def getMSRTrack2ServiceCode(tlv):
    track2 = tlv.getTag((0xdf,0xdb,0x06))[0].hex()
    if len(track2):
        worker = bytes.fromhex(track2).replace(b'\xaa', b'\x2a')
        track2Data = worker.decode('utf-8')
        m = re.search('^;([^=]+).([0-9]+).([^:]+)', track2Data)
        if len(m.groups()) >= 3:
            # set DDD format
            serviceCode = m.group(2)[4:7]
            if len(serviceCode):
                return serviceCode
    return ''


def setMSRTrack2DataAndExpiry(tlv, save = False):
    track2 = tlv.getTag((0xdf,0xdb,0x06))[0].hex()
    if len(track2):
        worker = bytes.fromhex(track2).replace(b'\xaa', b'\x2a')
        track2Data = worker.decode('utf-8')
        m = re.search('^;([^=]+).([0-9]+).([^:]+)', track2Data)
        if len(m.groups()) >= 3:
            # set YYMM to MMYY format
            expiry = m.group(2)[2:4]
            expiry += m.group(2)[:2]       
            if len(expiry):
                if save == True:
                    TC_TCLink.saveMSRTrack2AndExpiry(track2, expiry) 

# ---------------------------------------------------------------------------- #
# EMV Workflow
# ---------------------------------------------------------------------------- #

def setFirstGenContinueTransaction():
    continue_tran_tag = [
        [(0x9F, 0x02), AMOUNT],         # Amount
        [(0x9F, 0x03), AMTOTHER],       # Amount, other 
        CURRENCY_CODE, 
        COUNTRY_CODE, 
        ACQUIRER_ID,                    # TAG C2 acquirer id: ref. iccdata.dat
        [(0xDF, 0xA2, 0x18), [0x00]],   # Pin entry style
        #[ (0xDF, 0xA2, 0x0E), [0x5A] ], # Pin entry timeout
        [(0xDF, 0xA3, 0x07),            # Bit map display
        #[ (0x89), [0x00] ],             # Host Authorisation Code)
        AUTHRESPONSECODE,               # TAG 8A
        CONTINUE_REQUEST_TC if ISOFFLINE else CONTINUE_REQUEST_AAC, # TAG C0 object decision: 00=AAC, 01=TC
        [0x03, 0xE8]], 
        QUICKCHIP_ENABLED
    ]

    return (0xE0, continue_tran_tag)


def sendFirstGenAC(tlv, tid):
    global APPLICATION_LABEL, EMV_VERIFICATION

    # allow for decision on offline decline when issuing 1st GenAC (DNA)
    #EMV_VERIFICATION = 0x01
    EMV_VERIFICATION = 0x00

    # TEMPLATE E2 - DECISION REQUIRED
    # Should the device require a decision to be made it will return this template. The template could
    # contain one or more copies of the same data object with different value fields.
    # Issuing a Continue Transaction [DE, D2] instruction with template E0 containing the data object to
    # be used makes the decision for the device.
    # Should this template contain a single data element, there is still a decision to be made. In the case of
    # an AID it is the card that requests customer confirmation; returning the AID in the next Continue
    # instruction confirms the selection of this application.
    if tlv.tagCount(0xE2):
        EMV_VERIFICATION = 0x00
        if tlv.tagCount(0x50) >= 1 and tlv.tagCount((0x9F, 0x06)) >= 1:
            # This is app selection stuff
            appLabels = tlv.getTag(0x50)
            appAIDs = tlv.getTag((0x9F, 0x06))
            pan = tlv.getTag(0x5A)
            panBlacklisted = False
            if len(pan):
                panBlacklisted = TC_TransactionHelper.isPanBlackListed(conn, log, b2a_hex(pan[0]))
            APPLICATION_LABEL = [(0x50, ), bytearray(appLabels[0])]
            continue_tran_tag = [
                APPLICATION_LABEL,
                [(0x9F, 0x06), bytearray(appAIDs[0])],
                [(0x9F, 0x02), AMOUNTFORINQUIRY if ISBALANCEINQUIRY else AMOUNT],
                [(0x9F, 0x03), AMTOTHER],
                CURRENCY_CODE,
                COUNTRY_CODE,
                ACQUIRER_ID,                                    # TAG C2 acquirer id: ref. iccdata.dat
                #[ (0x89), [0x00] ],                            # Host Authorisation Code)
                AUTHRESPONSECODE,                               # TAG 8A
                [(0xDF, 0xA2, 0x18), [0x00]],                   # Pin entry style
                # note: this tag presence will cause DNA tests to fail - need to evaluate further when to include/exclude
                CONTINUE_REQUEST_TC if ISOFFLINE else CONTINUE_REQUEST_AAC, # TAG C0 object decision: 00=AAC, 01=TC
                QUICKCHIP_ENABLED
            ]
            # The terminal requests an ARQC in the 1st GENERATE AC Command.
            # The card returns an AAC to the 1st GENERATE AC Command.
            # The terminal does not send a 2nd GENERATE AC Command
            if panBlacklisted:
                continue_tran_tag.append(CONTINUE_REQUEST_TC)
            continue_tpl = (0xE0, continue_tran_tag)
            message = str(appLabels[0], 'iso8859-1')
            displayMsg('* APPLICATION LABEL *\n\t' + message, 2)
            # save Application Label
            TC_TCLink.saveEMVASCIITag((APPLICATION_LABEL))
    else:
        continue_tpl = setFirstGenContinueTransaction()

    log.log("CONTINUE TRANSACTION: GenAC1 -----------------------------------------------------------------------------")

    # CONTINUE TRANSACTION [DE, D2]
    # P1, Bit 0 = 1 - Return after Cardholder verification EMV step.
    conn.send([0xDE, 0xD2, EMV_VERIFICATION, 0x00], continue_tpl)

    return continue_tpl


def sendSecondGenAC(continue_tpl):
    # If we get here, we received Online Request. Continue with positive response.
    log.log("CONTINUE TRANSACTION: GenAC2 -----------------------------------------------------------------------------")

    # continue_tpl[1].append(ISSUER_AUTH_DATA)

    continue_trans_tag = [
        [(0x9F, 0x02), AMOUNTFORINQUIRY if ISBALANCEINQUIRY else AMOUNT],   # Amount
        [(0x9F, 0x03), AMTOTHER],
        CURRENCY_CODE,
        COUNTRY_CODE,
        ACQUIRER_ID,
        AUTHRESPONSECODE,
        [(0xDF, 0xA2, 0x18), [0x00]],                                       # PIN Entry style
        [(0xDF, 0xA3, 0x07), [0x03, 0xE8]],
        CONTINUE_REQUEST_TC if ISOFFLINE else CONTINUE_REQUEST_AAC,         # TAG C0 object decision:
                                                                            # 00=AAC, 01=TC
                                                                            # Issuer Authentication Data
        ISSUER_AUTH_DATA,
        QUICKCHIP_ENABLED
    ]
    continue2_tpl = (0xE0, continue_trans_tag)

    # CONTINUE TRANSACTION [DE, D2]
    #conn.send([0xDE, 0xD2, 0x01, 0x00], continue_tpl)
    conn.send([0xDE, 0xD2, 0x00, 0x00], continue2_tpl)

    # Ignore unsolicited automatically here
    status, buf, uns = getEMVAnswer(True)
    if status != 0x9000 and status != 0x9f22:
        log.logerr('Online Request has failed', hex(status))
        return -1

    return TLVParser(buf)


def processNoCashbackAllowed(tlv, tid):
    # expects 1st GENERATE AAC
    continue_tpl = sendFirstGenAC(tlv, tid)
    status, buf, uns = getEMVAnswer()
    # expects 2nd GENERATE AAC
    if status == 0x9000:
        sendSecondGenAC(continue_tpl)


def saveEMVHexMapTags(tlv):
    global AMTOTHER
    for tag in tlv:
        TC_TCLink.saveEMVHEXMapTag(tag)

    # TAG 9F03
    amountOther = hexlify(bytearray(AMTOTHER))
    TC_TCLink.saveEMVHEXMapTag(((0x9F, 0x03), amountOther.decode('utf-8').upper()), False)
    TC_TCLink.printEMVHexTags()


def set2ndGenACC(continue_tpl):
    # set 2nd GENERATE AAC request
    for i, item in enumerate(continue_tpl[1]):
        if item[0] == 0XC0:
            if item[1] != [0x01]:
                continue_tpl[1][i][1] = [0x01]
            break


# ---------------------------------------------------------------------------- #
# Contactless Workflow
# ---------------------------------------------------------------------------- #

# Inits contactless device
def initContactless():
    # Get contactless count
    ctls = False
    # GET CONTACTLESS STATUS [C0, 00]
    conn.send([0xC0, 0x00, 0x00, 0x00])
    status, buf, uns = getAnswer(True, False)
    if status == 0x9000:
        cnt = TC_TransactionHelper.getDataField(buf, TC_TransactionHelper.CONVERT_INT)
        if cnt >= 1:
            log.log("Detected ", cnt, " contactless devices")
            ctls = True
            # OPEN AND INITIALIZE CONTACTLESS READER [C0, 01]
            conn.send([0xC0, 0x01, 0x00, 0x00])
            status, buf, uns = getAnswer()
            # GET CONTACTLESS STATUS [C0, 00]
            conn.send([0xC0, 0x00, 0x01, 0x00])
            status, buf, uns = getAnswer()
        else:
            log.log('No contactless devices found')
    else:
        log.log('No contactless driver found')
    return ctls


# Start Contactless Transaction
def startContactless(preferredAID=''):
    global AMOUNT, AMTOTHER, DATE, TIME
    # Start Contactless transaction
    start_ctls_tag = [
        [(0x9F, 0x02), AMOUNT],         # amount
        [(0x9F, 0x03), AMTOTHER],       # cashback
        [(0x9A), DATE],                 # system date
        [(0x9F, 0x21), TIME],           # system time
        #[(0x9F,0x41), b'\x00\x01'],    # sequence counter
        AUTHRESPONSECODE,
        CURRENCY_CODE,                  # currency code
        COUNTRY_CODE                    # country code
    ]
    # Sale / Purchase with cashback not allowed here
    if TRANSACTION_TYPE != b'\x09':
        start_ctls_tag.append([(0x9C), TRANSACTION_TYPE])
    
    if len(preferredAID):
        # Preferred Application selected
        start_ctls_tag.append(preferredAID)
    else:
        # Application Identifier Terminal (AID)
        start_ctls_tag.append([(0x9F, 0x06), b'\x00\x01'])

    start_ctls_templ = (0xE0, start_ctls_tag)

    # START CONTACTLESS TRANSACTION [C0, A0]
    # P1
    #     Bit 0 (0x01)
    #     arm for Payment cards (transaction)
    #     Bit 1 (0x02)
    #     arm for MIFARE cards (VIPA 6.2.0.11+ on V/OS)
    #     Bit 3 (0x08)
    #     force transaction in offline
    #     Bit 4 (0x10)
    #     prioritize MIFARE before payment
    #     Bit 5 (0x20)
    #     (VOS2 devices only) arm for VAS (Value Added Services) transaction
    #     (wallet/loyalty)
    #     Bit 6 (0x40)
    #     force CVM (transaction forces processing CVM regardless of CVM Limit configured)
    #     * this feature is used primarily for SCA
    #     Bit 7 (0x80)
    #     stop on MIFARE command processing errors (only valid when bit 1 is set)
    conn.send([0xC0, 0xA0, 0x01, 0x00], start_ctls_templ)

    log.log('Starting Contactless transaction')


# from a list of AIDS, a selection needs to be made to process Contactless workflows - a second tap is required
def processCtlsAIDList(tlv):
    # BF0C Tag Listing AIDS
    if tlv.tagCount(0xA5):
        fci_value = tlv.getTag((0xA5))[0]

        value = hexlify(fci_value).decode('ascii')
        #log.log("DATA:" + value )

        tlvp = TLVPrepare()
        # even number of bytes
        value += '9000'
        buf = unhexlify(value)
        tlv_tags = tlvp.parse_received_data(buf)
        tags = TLVParser(tlv_tags)

        aidList = []
        lblList = []

        for item in tags:
            value = hexlify(item[1]).decode('ascii')
            # log.log(value)
            # 4f: AID
            aid = TC_TransactionHelper.getValue('4f', value)
            #log.log("AID:" + aid)
            aidList.append(aid)
            # 50: LABEL
            label = TC_TransactionHelper.getValue('50', value)
            label = bytes.fromhex(label)
            label = label.decode('ascii')
            #log.log("LABEL:" + label)
            lblList.append(label)

        # only process multi-lists
        if len(aidList) <= 1:
            return ''

        log.log('We have ', len(lblList), ' applications')

        if len(lblList) != len(aidList):
            log.logerr('Invalid response: AID count ', len(aidList), ' differs from Labels count ', len(lblList))
            exit(-1)

        # TODO: multi-message not allowed
        # sending choice to terminal in ASCII formatted string
        #message = ''
        # for i in range(len(aidList)):
        #    message += "".join("{0:x}".format(ord(c)) for c in lblList[i])
        #    message += '0a'

        # TEST MESSAGE
        #message = '5061676f42414e434f4d41540a4d61657374726f0a'
        #slen =  len(message) // 2
        #length = hex( slen )
        #choice = requestChoice( message, length[2:] )

        # Console workflow
        for i in range(len(aidList)):
            log.log('App', i+1, ': ' + aidList[i] + ' - [' + lblList[i] + ']')
        sel = -1
        log.log('Select App: ')

        while True:
            # Note: The below will work for up to 9 apps...
            if kbhit():
                try:
                    sel = ord(getch())
                except:
                    print('invalid key!')
                #TC_transtest_all_autoselect_EMV.log.log('key press ', sel)
                if sel > 0x30 and sel <= 0x30 + len(lblList):
                    sel -= 0x30  # to number (0 .. x)
                    break
                elif sel == 27:
                    # ABORT [D0 FF]
                    return AbortTransaction()

                print(' Invalid selection, please pick valid number! ')

            if conn.is_data_avail():
                status, buf, uns = getEMVAnswer()
                if status != 0x9000:
                    log.logerr('Transaction terminated with status ', hex(status))
                    return -1
                break

        # user made a selection
        if sel >= 0:
            sel = sel - 1
            log.log('Selected ', sel)
            PREFERRED_AID = [(0x9F, 0x06), bytes.fromhex(aidList[sel])]
            return PREFERRED_AID


# Processes contactless continue
def processCtlsContinue():

    continue_ctls_tag = [
        ACQUIRER_ID,
        CONTINUE_REQUEST_AAC,
        AUTHRESPONSECODE
    ]
    continue_ctls_templ = (0xE0, continue_ctls_tag)

    # CONTINUE CONTACTLESS TRANSACTION [C0 A1]
    conn.send([0xC0, 0xA1, 0x00, 0x00], continue_ctls_templ)

    status, buf, uns = getAnswer()
    log.log('Waiting for Contactless Continue')
    while True:
        status, buf, uns = getAnswer(False)
        if uns:
            break
        log.logerr('Unexpected packet detected, ', TLVParser(buf))


# Cancel contactless reader
def cancelContactless():
    log.logerr("Stopping Contactless transaction")
    # CANCEL CONTACTLESS TRANSACTION [C0 C0]
    conn.send([0xC0, 0xC0, 0x00, 0x00])
    status, buf, uns = getAnswer()
    # Ignore unsolicited as the answer WILL BE unsolicited...
    status, buf, uns = getAnswer(False)


# ---------------------------------------------------------------------------- #
# EMV Contact Workflow
# ---------------------------------------------------------------------------- #

def processEMV(tid):

    global AMOUNT, DATE, TIME, OFFLINERESPONSE, AMTOTHER, SIGN_RECEIPT, EMV_VERIFICATION, TRANSACTION_TYPE
    global OnlinePinContinueTPL
    
    transaction_counter = b'\x00\x01'

    # Create localtag for transaction
    start_trans_tag = [
        [(0x9C), TRANSACTION_TYPE],
        [(0x9F, 0x02), AMOUNTFORINQUIRY if ISBALANCEINQUIRY else AMOUNT],
        [(0x9F, 0x03), AMTOTHER],
        [(0x9A), DATE],
        [(0x9F, 0x21), TIME],
        CURRENCY_CODE,
        COUNTRY_CODE,
        [(0x9F, 0x41), transaction_counter],        # transaction counter
        [(0xDF, 0xA2, 0x18), b'\x00'],              # pin entry style
        [(0xDF, 0xA2, 0x14), b'\x01'],              # Suppress Display
        [(0xDF, 0xA2, 0x04), b'\x01'],              # Application selection using PINPAD
        #[(0xDF, 0xDF, 0x0D), b'\x02']              # Don't force transaction online
    ]
    start_templ = (0xE0, start_trans_tag)

    # IPA5 transaction sequence counter
    transaction_counter = hexlify(bytearray(transaction_counter))
    TC_TCLink.saveEMVHEXMapTag(((0x9F, 0x41), transaction_counter.decode('utf-8').upper()), False)

    log.log("START TRANSACTION: ***************************************************************************************")

    # -------------------------------------------------------------------------
    # START TRANSACTION [DE D1]
    conn.send([0xDE, 0xD1, 0x00, 0x00], start_templ)

    while True:
        # sleep(1)
        #conn.send([0xD0, 0xFF, 0x00, 0x00])
        status, buf, uns = getEMVAnswer()
        if status != 0x9000:
            if status == 0x9F28:
                log.logerr("TECHNICAL FALLBACK")
                displayMsg(DM_9F28, 3)
                return processMagstripeFallback(tid)
            else:
                if status == 0x9F25:
                    displayMsg(DM_9F25, 2)

                if status == 0x9F42:
                    displayMsg(DM_9F42, 2)
                    processNoCashbackAllowed(TLVParser(buf), tid)

                log.logerr('Transaction terminated with status ', hex(status))
                return -1

        if uns and status == 0x9000:
            tlv = TLVParser(buf)
            if tlv.tagCount(0xE6) != 0:
                log.log('Multi application card!')
                continue
            else:
                log.log('Ignoring unsolicited packet ', tlv)
                continue
        else:
            tlv = TLVParser(buf)

            # AID Selection Prompt
            if tlv.tagCount(0xE2):
                if tlv.tagCount(0x50) > 1 and tlv.tagCount((0x9F, 0x06)) > 1:
                    applicationSelection(tlv)
                    # requestAIDChoice(tlv)
                    # displayAidChoice(tlv)
                    continue

                # Check for Contact EMV Capture
                #print(">>> EMV Data 0 ff7f", tlv.tagCount((0xFF,0x7F)))
                # TC_TCLink.saveCardData(tlv)
                #print(">> first data", str(tlv))
                # if tlv.tagCount(0xE2):
                #    TC_TCLink.saveEMVData(tlv,0xE2)

            break

    # Let's check VSP
    tlv = TLVParser(buf)
    TC_TransactionHelper.vspDecrypt(tlv, tid, log)

    # Check for Contact EMV Capture
    #print(">>> EMV Data 1 ff7f", tlv.tagCount((0xFF,0x7F)))
    TC_TCLink.saveCardData(tlv)
    print(">> before continue: ", str(tlv))

    # save miscellaneous tags
    saveEMVHexMapTags(tlv)

    # -------------------------------------------------------------------------
    # 1st Generation AC
    continue_tpl = sendFirstGenAC(tlv, tid)

    # Template E6 requests for PIN, so allow Template E4 to just submit the transaction (without collecting PIN again)
    hasPINEntry = False
    pinTryCounter = 0x00

    while True:
        # process response
        status, buf, uns = getEMVAnswer()
        if status != 0x9000:
            log.logerr('Transaction terminated with status ', hex(status))
            # Terminal declines when a card replies with a TC (Approve) in response to an ARQC (go online) request in 1st GenAC (DNA)
            if EMV_VERIFICATION == 0x00:
                displayMsg("DECLINED: OFFLINE", 2)
            return -1

        tlv = TLVParser(buf)

        if uns and status == 0x9000:
            # print(tlv)
            # device has entered a wait state
            if tlv.tagCount(0xE6):
                message = tlv.getTag((0xC4))
                if (len(message)):
                    message = str(message[0], 'iso8859-1')
                    log.log(message)
                pinTryCounter = tlv.getTag((0xC5))[0]
                performUserPINEntry()
                hasPINEntry = True
                # let device proceed to next step
                continue

            else:
                log.log('Ignoring unsolicited packet ', tlv)
                continue
        else:
            print(">> after continue first pass: ", str(tlv))

            # validate this is necessary: tags missing 8A and 9F27 in card log
            if tlv.tagCount(0xE0):
                if ISOFFLINE:
                    TC_TCLink.saveEMVData(tlv, 0xE0)

                if (tlv.tagCount((0x9F, 0x34)) >= 1):

                    cvm_value = TC_TransactionHelper.getCVMResult(tlv)
                    # NOT AN EROR, JUST EASIER TO FIND IN THE TERMINAL OUTPUT
                    log.logerr('CVM REQUESTED:', cvm_value)

                    #if cvm_value == "ONLINE PIN":
                    #   return OnlinePinTransaction(tlv, EMV_CARD_INSERTED, continue_tpl)

                    if cvm_value == "SIGNATURE":
                        SIGN_RECEIPT = True

            if tlv.tagCount(0xE4):

                # check Terminal Capabilities reports correctly - CONTACTLESS WORKFLOW
                reportTerminalCapabilities(tlv)

                cvm_value = TC_TransactionHelper.getCVMResult(tlv)
                # NOT AN EROR, JUST EASIER TO FIND IN THE TERMINAL OUTPUT
                log.logerr('CVM REQUESTED:', cvm_value)

                # if cvm_value == "ONLINE PIN":
                #    hasPINEntry = getOnlinePIN(tlv)
                #    if hasPINEntry:
                #         # send to process online PIN entry
                #        response = TC_TCLink.processPINTransaction(OnlineEncryptedPIN, OnlinePinKSN)
                #        log.log("PIN response: "+ response)
                #        displayMsg(response.upper(), 3)
                #        return -1

                # review: should we always send the transaction online?
                # DNA: requires 2nd GENERATE AC decline (AAC)
                # if args.online == "y" and cvm_value == "ONLINE PIN":
                if cvm_value == "ONLINE PIN":
                    if hasPINEntry == True:
                        # expect Template E6 already collected PIN: retrieve PIN KSN/ENCRYPTED DATA
                        OnlinePinInTemplateE6(tlv, EMV_CARD_INSERTED, continue_tpl)
                        # save continue tpl in case of PIN retry
                        OnlinePinContinueTPL = continue_tpl
                        break
                    # request PIN from user
                    return OnlinePinTransaction(tlv, EMV_CARD_INSERTED, continue_tpl)

                if cvm_value == "SIGNATURE":
                    SIGN_RECEIPT = True

                if cvm_value == "PLAIN PIN":
                    # verify PIN entry
                    # verifyOfflinePIN(pinTryCounter)
                    # set 2nd GENERATE AAC request
                    if ISBALANCEINQUIRY == False:
                        set2ndGenACC(continue_tpl)

                TC_TCLink.saveEMVData(tlv, 0xE4)

                break

            if tlv.tagCount(0xE3):
                log.log("Transaction approved offline")
                displayMsg("APPROVED", 2)
                return -1

            if tlv.tagCount(0xE5):
                log.log("Transaction declined offline")
                displayMsg("DECLINED: OFFLINE", 2)
                return -1

            break

    # -------------------------------------------------------------------------
    # 2nd Generation AC
    tlv = sendSecondGenAC(continue_tpl)

    if tlv == -1:
        return -1

    if tlv.tagCount(0xE3):
        log.log("Transaction approved offline")
        # Check for Contact EMV Capture
        #print(">>> EMV Data 2 ff7f", tlv.tagCount((0xFF,0x7F)))
        TC_TCLink.saveCardData(tlv)
        displayMsg("APPROVED", 2)
        return -1

    if tlv.tagCount(0xE4) and ISOFFLINE:  # Online Action Required

        log.log("CONTINUE TRANSACTION: GenAC2 [TEMPLATE E4] ---------------------------------------------------------------")

        # -------------------------------------------------------------------------
        # 2nd GenAC
        tlv = sendSecondGenAC(continue_tpl)

        if tlv == -1:
            return -1

        TC_TCLink.saveEMVData(tlv, 0xE4)

        return 3

    if tlv.tagCount(0xE5):
        log.log("Transaction declined")

        # Check for Contact EMV Capture
        #print(">>> EMV Data 3 ff7f", tlv.tagCount((0xFF,0x7F)))
        TC_TCLink.saveCardData(tlv)
        return 6 if hasPINEntry else 2

    # Check for Contact EMV Capture
    #print(">>> EMV Data 4 ff7f", tlv.tagCount((0xFF,0x7F)))
    TC_TCLink.saveCardData(tlv)

    return 3


# Prompts for card insertion
def promptForCard():
    # DISPLAY [D2, 01]
    conn.send([0xD2, 0x01, 0x0D, 0x01])
    status, buf, uns = getAnswer()


# Prompts for card reinsertion
def promptForReinsertCard():
    # DISPLAY [D2, 01]
    conn.send([0xD2, 0x01, 0x14, 0x01])
    status, buf, uns = getAnswer()


def promptForSwipeCard():
    # DISPLAY [D2, 01]
    conn.send([0xD2, 0x01, 0x2B, 0x01])
    status, buf, uns = getAnswer()


# ---------------------------------------------------------------------------- #
# Main function
# ---------------------------------------------------------------------------- #

def processTransaction(args):

    global AMOUNT, DATE, TIME, ONLINE, OFFLINERESPONSE, AMTOTHER, DEVICE_UNATTENDED
    global TRANSACTION_TYPE, ISBALANCEINQUIRY, FALLBACK_TYPE
    global OnlineEncryptedPIN, OnlinePinKSN, OnlinePinContinueTPL

    TC_TCLink.SetProperties(args, log)
    if args.amtother != 0:
        AMOUNT = TC_TransactionHelper.bcd(args.amount + args.amtother, 6)
        AMTOTHER = TC_TransactionHelper.bcd(args.amtother, 6)
    else:
        AMOUNT = TC_TransactionHelper.bcd(args.amount, 6)

    now = datetime.datetime.now()
    DATE = TC_TransactionHelper.bcd(now.year % 100) + TC_TransactionHelper.bcd(now.month) + TC_TransactionHelper.bcd(now.day)
    TIME = TC_TransactionHelper.bcd(now.hour % 100) + TC_TransactionHelper.bcd(now.minute) + TC_TransactionHelper.bcd(now.second)
    #print("Amount", str(AMOUNT), "vs", str(b'\x00\x00\x00\x00\x01\x00'))
    #print("Date", str(DATE), "Time", str(TIME))
    req_unsolicited = conn.connect()
    if req_unsolicited:
        # Receive unsolicited
        log.log('Waiting for unsolicited')
        #status, buf, uns = getAnswer(False)
        #log.log('Unsolicited', TLVParser(buf) )

    # abort current transaction
    AbortTransaction()

    # RESET DEVICE [D0, 00]
    buf = ResetDevice()

    tlv = TLVParser(buf)
    tid = tlv.getTag((0x9F, 0x1e))

    if len(tid):
        tid = str(tid[0], 'iso8859-1')
        TC_TCLink.setDeviceSerial(tid)
        log.log('Terminal TID:', tid)
    else:
        tid = ''
        log.logerr('Invalid TID (or cannot determine TID)!')

    deviceUnattended = tlv.getTag((0xDF, 0x0D))
    if len(deviceUnattended):
        deviceUnattended = str(deviceUnattended[0], 'iso8859-1')
        isUnattended = deviceUnattended.upper().find("UX")
        if isUnattended == 0:
            deviceUnattended = "y"
        else:
            deviceUnattended = "n"
        TC_TCLink.setDeviceUnattendedMode(deviceUnattended)
        log.log('DEVICE UNATTENDED:', deviceUnattended)
    else:
        deviceUnattended = ''
        log.logerr('Invalid DEVICE (or cannot determine TYPE)!')

    # DISPLAY [D2 01]
    conn.send([0xD2, 0x01, 0x01, 0x01])
    status, buf, uns = getAnswer()

    # CARD STATUS [D0 60]
    startMonitoringCardStatus()
    status, buf, uns = getAnswer(False)

    cardState = EMV_CARD_REMOVED
    if uns:
        # Check for insertion unsolicited message
        tlv = TLVParser(buf)
        if tlv.tagCount(0x48):
            cardState = EMVCardState(tlv)

    ctls = 0x00 if ISBALANCEINQUIRY else initContactless()
    if (cardState != EMV_CARD_INSERTED):
        if (ctls):
            startContactless()
            status, buf, uns = getAnswer()
        else:
            promptForCard()
        log.log('**** WAIT FOR CARD INSERTION / TAP / SWIPE ****')

        tranType = 0
        result = 0
        msrSwipeCount = 0
        ignoreSwipe = False

        while True:
            # status, buf, uns = getAnswer(False) # Get unsolicited ONLY
            status, buf, uns = getAnswer(False, False)  # Get unsolicited ONLY
            if uns and status == 0x9000:
                # Check for insertion unsolicited message
                tlv = TLVParser(buf)

                if tlv.tagCount(0x48):
                    cardState = EMVCardState(tlv)
                    magState = MagstripeCardState(tlv)
                    # Ignore failed swipes
                    if ctls and (cardState == EMV_CARD_INSERTED or magState == MAGSTRIPE_TRACKS_AVAILABLE):
                        # Cancel Contactless first
                        cancelContactless()
                    if cardState == EMV_CARD_INSERTED:
                        log.log("Card inserted, process EMV transaction!")
                        result = processEMV(tid)
                        if args.online == "y" and result != -1:
                            return
                        if result == 5:  # msr fallback result
                            tranType = 2
                        if result == 6:
                            tranType = 6
                        else:
                            if result != -1:
                                tranType = 1
                        break
                    else:
                        if cardState == ERROR_UNKNOWN_CARD:
                            log.log('Unknown card type ')
                            displayMsg("UNKNOWN CARD TYPE\n\tREMOVE AND RETRY", 2)
                            if msrSwipeCount == args.msrfallback:
                                log.log('Entering MSR Fallback')
                                msrSwipeCount = 1
                                processMagstripeFallback(tid)
                                tranType = 2
                                break
                            removeEMVCard()
                            promptForReinsertCard()
                            log.log('**** WAIT FOR CARD INSERTION / TAP / SWIPE ****')
                            msrSwipeCount += 1
                            continue
                    if not ignoreSwipe:
                        if magState == ERROR_UNKNOWN_CARD:
                            log.logerr('Swipe has failed, there are no tracks!')
                            continue
                        else:
                            if magState == MAGSTRIPE_TRACKS_AVAILABLE:
                                msrSwipeCount += 1
                                if msrSwipeCount > args.msrfallback or CardIsEMVCapable(tlv) == False:
                                    if msrSwipeCount > args.msrfallback:
                                        log.log('Entering MSR Fallback')
                                    TC_TransactionHelper.vspDecrypt(tlv, tid, log)
                                    if tlv.tagCount((0xdf,0xdb,0x06)):
                                        setMSRTrack2DataAndExpiry(tlv)
                                    tranType = 2
                                    break
                                else:
                                    log.log(f'Card swiped! {msrSwipeCount}/{args.msrfallback} until MSR fallback.')
                                    promptForReinsertCard()
                                    log.log('**** WAIT FOR CARD INSERTION / TAP / SWIPE ****')
                                    continue
                            else:
                                # consider this a possible EMV fallback scenario for Verifone ICC Testing
                                msrSwipeCount += 1
                                log.log(f'Card swiped! {msrSwipeCount}/{args.msrfallback} until MSR fallback.')
                                if msrSwipeCount == args.msrfallback:
                                    log.log('Entering MSR Fallback')
                                    promptForSwipeCard()
                                    log.log('**** WAIT FOR CARD SWIPE ****')
                                    processMagstripeFallback(tid)
                                    tranType = 2
                                    break
                                else:
                                    TC_TransactionHelper.displayEncryptedTrack(tlv)
                                    break

                    log.log("Waiting for next occurrance!")
                    continue

                # Check for unsolicited keyboard status
                if tlv.tagCount((0xDF, 0xA2, 0x05)):
                    kbd_tag_val = tlv.getTag((0xDF, 0xA2, 0x05), TLVParser.CONVERT_INT)[0]
                    log.log("Keyboard status, keypress ", hex(kbd_tag_val), 'h')
                    if kbd_tag_val == 27:
                        break
                    continue
                TC_TCLink.saveCardData(tlv)

                # TAG FF7F
                #vsdSREDTemplateDebugger(tlv, tid)

                # TEMPLATE E3: TRANSACTION APPROVED
                if tlv.tagCount(0xE3):  # E3 = transaction approved
                    log.log("Approved contactless EMV transaction!")
                    displayMsg("APPROVED", 2)
                    # todo: vsp decrypt!
                    TC_TransactionHelper.vspDecrypt(tlv, tid, log)
                    TC_TCLink.saveEMVData(tlv, 0xE3)
                    tranType = 4
                    break

                # TEMPLATE E4: ONLINE ACTION REQUIRED
                if tlv.tagCount(0xE4):

                    # Terminal Capabilites
                    reportTerminalCapabilities(tlv)

                    TC_TransactionHelper.vspDecrypt(tlv, tid, log)
                    TC_TCLink.saveEMVData(tlv, 0xE4)
                    # ADDED 08312020. Extract 9f34 tag (online pin entry required?)
                    if (tlv.tagCount((0x9F, 0x34)) >= 1):
                        cvm_result = tlv.getTag((0x9F, 0x34))[0]
                        encrypted_pin = (cvm_result[0] & 0x0f)
                        # Indicate CVM type
                        switcher = {
                            2: "ONLINE PIN",
                            14: "SIGNATURE",
                            15: "NO CVM PERFORMED"
                        }
                        cvm_value = switcher.get(encrypted_pin, "UNKNOWN CVM TYPE")
                        # NOT AN EROR, JUST EASIER TO FIND IN THE TERMINAL OUTPUT
                        log.logerr('CVM REQUESTED:', cvm_value)

                        # note: this might need review since it was only tested for AMEX CLESS
                        if (encrypted_pin == 0x02):
                            return OnlinePinTransaction(tlv, cardState, setFirstGenContinueTransaction())

                    if cardState != EMV_CARD_INSERTED:
                        processCtlsContinue()
                        tranType = 5

                    break

                # TEMPLATE E5: TRANSACTION DECLINED
                if tlv.tagCount(0xE5):
                    tranType = 4
                    TC_TCLink.saveEMVData(tlv, 0xE5)
                    log.logerr('TRANSACTION OFFLINE DECLINED')
                    performCleanup()
                    return

                # TEMPLATE E7: CONTACTLESS MAGSTRIPE TRANSACTION
                if tlv.tagCount(0xE7):
                    # Terminal Capabilites
                    reportTerminalCapabilities(tlv)
                    TC_TransactionHelper.vspDecrypt(tlv, tid, log)
                    TC_TCLink.saveEMVData(tlv, 0xE7)
                    processCtlsContinue()
                    tranType = 3
                    break

                if status != 0x9000:
                    if status == 0x9F33:  # Fallforward to ICC / Swipe
                        promptForCard()
                        # No need to exit the loop - swipe is not active now
                        continue
                    else:
                        if status == 0x9F34:  # Fallforward to ICC only
                            promptForCard()
                            # No need to exit the loop - ctls is not active now, but we have to disable swipes
                            ignoreSwipe = True
                            continue

            # check for termination state

            # 0x9f28: unsupported card
            # 0x9f35: consumer CVM - contactless workflow
            if status == 0x9f28 or status == 0x9f35:
                if status == 0x9f28:
                    displayMsg(DM_9F28, 3)
                if status == 0x9f35:
                    displayMsg(DM_9F35, 3)
                log.log('*** COMPLETED WITH EXPECTED ERROR IN STATE ***')
                log.logerr('Pinpad reported error ', hex(status))
                performCleanup()
                return

            if status == 0x9f31:
                displayMsg(DM_9F31, 3)
                log.log('*** COMPLETED WITH EXPECTED ERROR IN STATE ***')
                log.logerr('Pinpad reported error ', hex(status))
                performCleanup()
                return

            if status == 0x9f33:
                tlv = TLVParser(buf)
                # TEMPLATE A5: CUSTOM TEMPLATE
                if tlv.tagCount(0xA5):
                    if tlv.tagCount((0x9F, 0x38)):
                        pdol_value = tlv.getTag((0x9F, 0x38))[0]
                        if len(pdol_value) > 2:
                            if pdol_value[0] == 0x9F:
                                switcher = {
                                    0x35: "TERMINAL TYPE:",
                                    0x6E: "CLESS ENHANCED CAPABILITIES:",
                                }
                                pdol_type_value = switcher.get(pdol_value[1], "UNKNOWN PDOL TYPE")
                                log.logerr(pdol_type_value, pdol_value[2])

                                if len(pdol_value) > 5:
                                    if pdol_value[3] == 0x9F:
                                        switcher = {
                                            0x35: "TERMINAL TYPE:",
                                            0x6E: "CLESS ENHANCED CAPABILITIES:",
                                        }
                                        pdol_type_value = switcher.get(pdol_value[4], "UNKNOWN PDOL TYPE")
                                        log.logerr(pdol_type_value, pdol_value[5])
                    performCleanup()
                return

            if status == 0x9f34:
                displayMsg(DM_9F34, 3)
                log.log('*** COMPLETED WITH EXPECTED ERROR IN STATE ***')
                log.logerr('Pinpad reported error ', hex(status))

                # Restart request for card insertion only
                promptForCard()
                # No need to exit the loop - ctls is not active now, but we have to disable swipes
                ignoreSwipe = True
                continue

            if status == 0x9F41:
                displayMsg(DM_9F41, 3)
                processPinBypass()
                continue

            if tlv.tagCount(0x6F):
                preferredAid = processCtlsAIDList(tlv)
                if len(preferredAid):
                    startContactless(preferredAid)
                    status, buf, uns = getAnswer()
                    continue
                break

            log.logerr("Invalid packet detected, ignoring it!")
            print('E4: ', tlv.tagCount(0xE4))
            print(tlv)
    else:
        log.log("Card already inserted!")
        result = processEMV(tid)
        if args.online == "y":
            return
        tranType = 1

    #
    # After loop - DON'T ENTER WHEN PREVIOUS RESULTS INDICATE FAILURE
    #
    if result != -1:

        if tranType == 1:
            # If card still inserted, ask for removal
            removeEMVCard()
        else:
            # Delay for some CLess messaging to complete; may be able to replace with loop awaiting card removed from field
            sleep(0.500)

        # Check for Card data
        TC_TCLink.saveCardData(tlv)

        # Processing Transaction
        # DISPLAY [D2 01]
        conn.send([0xD2, 0x01, 0x02, 0x01])
        sleep(3)

        # Check for Contact EMV Capture
        #print(">>> tranType", tranType, "ff7f", tlv.tagCount((0xFF,0x7F)))
        #print(">>> tranType", tranType)
        response = ""
        if tranType == 1:
            #print(">>> ff7f", tlv.tagCount((0xFF,0x7F)))
            response = TC_TCLink.processEMVTransaction()
        # Check for swipe
        if tranType == 2:
            #print(">>> ff7f", tlv.tagCount((0xFF,0x7F)))
            response = TC_TCLink.processMSRTransaction()
        # Check for contactless magstripe
        if tranType == 3:
            #print(">>> ff7f", tlv.tagCount((0xFF,0x7F)))
            response = TC_TCLink.processCLessMagstripeTransaction()
        # Check for Offline approve/decline
        if tranType == 4:  # Should tags be captured for an Offline Decline case and sent to TCLink?
            #print(">>> ff7f", tlv.tagCount((0xFF,0x7F)))
            response = TC_TCLink.processEMVTransaction()
        # Check for CLess
        if tranType == 5:
            #print(">>> ff7f", tlv.tagCount((0xFF,0x7F)))
            response = TC_TCLink.processEMVTransaction()
        # online PIN transaction
        if tranType == 6:
            log.log('PROCESS ONLINE PIN TRANSACTION: ------------------------------------------------------------------------')
            response = TC_TCLink.processPINTransaction(OnlineEncryptedPIN, OnlinePinKSN)
            log.log("PIN response: " + response)
            if response != "approved":
                displayMsg('Invalid PIN:' + response, 3)
                OnlinePinTransaction(tlv, cardState, OnlinePinContinueTPL, True, 1)
            # delay to complete
            removeEMVCard()
        # offline transaction
        if tranType == 0:
            response = "OFFLINE: " + OFFLINERESPONSE

        declinetype = ""

        # Transaction Status
        if len(response):
            if response == "decline":
                declinetype = TC_TCLink.getDeclineType()
                if len(declinetype):
                    response = response + ": " + declinetype
            else:
                if response == "error":
                    response = "decline: error"
            displayMsg(response.upper(), 3)
            if response == 'approved' and SIGN_RECEIPT:
                displayMsg("PLEASE SIGN RECEIPT", 3)
    else:
        if EMVCardState(tlv) == EMV_CARD_INSERTED:
            removeEMVCard()

    #
    # RETURN DEVICE TO USABLE STATE BEFORE EXITING
    #
    stopMonitoringKeyPresses()

    # DISPLAY [D2 01]
    conn.send([0xD2, 0x01, 0x01, 0x00])
    log.log('*** RESET DISPLAY ***')
    status, buf, uns = getAnswer()


# -------------------------------------------------------------------------------------- #
# MAIN APPLICATION ENTRY POINT
# -------------------------------------------------------------------------------------- #
if __name__ == '__main__':

    log = getSyslog()

    log.logerr("TESTHARNESS v" + VERSION_LBL)

    arg = util.get_argparser()
    arg.add_argument('--custid', dest='custid', default='1152701', type=int,
                     help='TC CustID for transaction')
    arg.add_argument('--password', dest='password', default='testipa1',
                     help='TC Password for transaction')
    arg.add_argument('--action', dest='action', default='sale',
                     help='TC Action for transaction')
    arg.add_argument('--amount', dest='amount', default='100', type=int,
                     help='Amount of transaction')
    arg.add_argument('--amtother', dest='amtother', default='0', type=int,
                     help='Amount other')
    arg.add_argument('--cashback', dest='cashback', default=None, type=int,
                     help='Cashback Amount')
    arg.add_argument('--operator', dest='operator', default=getpass.getuser(),
                     help='Operator for transaction')
    arg.add_argument('--lanenumber', dest='lanenumber', default=None,
                     help='Lane Number for transaction')
    arg.add_argument('--online', dest='online', default=None,
                     help='Online PIN')
    arg.add_argument('--pinattempts', dest='pinattempts', default=1, type=int,
                     help='Online PIN attempts allowed')
    arg.add_argument('--msrfallback', dest='msrfallback', default=1, type=int,
                     help='Insert attempts allowed before MSR fallback')
    arg.add_argument('--device_pinpad_capable', dest='device_pinpad_capable', default='n',
                     help='UNATTENDED device pin capability only')
    arg.add_argument('--validateAmount', dest='validateAmount', default='y',
                     help='Ask user to validate amount')
    arg.add_argument('--partialauth', dest='partialauth', default='n',
                     help='Partial authorization')

    args = util.parse_args()

    # Transaction Amount
    if args.validateAmount == 'y':
        TransactionAmount = input("ENTER AMOUNT (" + str(args.amount) + "): ")

        if len(TransactionAmount) > 1:
            value = int(TransactionAmount)
            if value > 0:
                args.amount = value

    if args.amount != 0:
        log.log('TRANSACTION AMOUNT: $', args.amount)
        if TRANSACTION_TYPE == b'\x09':
            args.cashback = "0300"
            log.log('CASHBACK AMOUNT   : $', args.cashback)
    else:
        # set balance inquiry in launch.json
        if args.action == 'verify':
            TRANSACTION_TYPE = b'\x30'
            ISBALANCEINQUIRY = True
        log.log('BALANCE INQUIRY? - TRANSACTION TYPE=' +
                hexlify(TRANSACTION_TYPE).decode('ascii'))

    if(args.amtother != 0):
        log.log('TRANSACTION AMOUNT OTHER: $', args.amtother)
        log.log('TOTAL TRANSACTION AMOUNT: $', args.amount + args.amtother)

    conn = connection.Connection()

    #print('custid=' + str(args.custid) + ",password=" + str(args.password) + ",action=" + str(args.action))
    #print('DEVICE PINPAD CAPABLE=' + str(args.device_pinpad_capable))

    utility.register_testharness_script(
        partial(processTransaction, args))
    utility.do_testharness()
