#!/usr/bin/python3
'''
Created on 03-01-2020

@authors: Matthew_H
'''

from TC_testharness import *
import TC_testharness.utility as util
from functools import partial
from TC_testharness.tlvparser import TLVParser
from TC_testharness.tlvparser import TLVPrepare
from sys import exit
from TC_testharness.syslog import getSyslog
from TC_testharness.utility import getch, kbhit
from binascii import hexlify, unhexlify
from time import sleep
import traceback
from datetime import datetime
import pickle

import win32com.client
tclink = win32com.client.Dispatch("TCLinkCOM.TClink")

LOG_INTERNAL_DATA = False

LOG = None
ENCRYPTED_TRACK_IV = ''
ENCRYPTED_TRACK_KSN = ''
ENCRYPTED_TRACK_DATA = ''
MSR_TRACK2_DATA = ''
MSR_EXPIRY_DATA = ''
DEVICE_SERIAL = ''
DEVICE_UNATTENDED = ''
POS_ENTRY_MODE = ''
# Default if not set in Vault; see John Luong email Feb 13, 2020 9:10am, RE: Question on 'emv_processingcode' (attached US 9334)
PLATFORM = 'firstdatarapidconnect'
EMV_PROCESSING_CODE = ''
EMV_TAGS = {}

DEVICE_PINPAD_CAPABLE = 'n'
PARTIAL_AUTH = 'n'
IS_FALLBACK = 'n'
FALLBACK_TYPE = ''
ISBALANCEINQUIRY = False

# EMV tags to map to TCLink as Hex data
EMV_TAGS_HEX_MAP = {
    (0x4F, ): 'emv_4f_applicationidentifiericc',
    (0x5F, 0x24): 'emv_5f24_applicationexpirationdate',
    (0x5F, 0x28): 'emv_5f28_issuercountrycode',
    (0x5F, 0x2A): 'emv_5f2a_transactioncurrencycode',
    (0x5F, 0x2D): 'emv_5f2d_languagepreference',
    (0x5F, 0x30): 'emv_5f30_servicecode',
    (0x5F, 0x34): 'emv_5f34_cardsequenceterminalnumber',
    (0x82, ): 'emv_82_applicationinterchangeprofile',
    (0x84, ): 'emv_84_dedicatedfilename',
    (0x8E, ): 'emv_8e_cardholderverificationmethodlist',
    (0x91, ): 'emv_91_issuerauthenticationdata',
    (0x95, ): 'emv_95_terminalverificationresults',
    (0x9A, ): 'emv_9a_transactiondate',
    (0x9B, ): 'emv_9b_transactionstatusinformation',
    (0x9C, ): 'emv_9c_transactiontype',
    (0x9F, 0x02): 'emv_9f02_amountauthorized',
    (0x9F, 0x03): 'emv_9f03_amountother',
    (0x9F, 0x06): 'emv_9f06_applicationidentifierterminal',
    (0x9F, 0x07): 'emv_9f07_applicationusagecontrol',
    (0x9F, 0x08): 'emv_9f08_applicationversionnumbericc',
    (0x9F, 0x09): 'emv_9f09_applicationversionnumberterminal',
    (0x9F, 0x0D): 'emv_9f0d_issueractioncodedefault',
    (0x9F, 0x0E): 'emv_9f0e_issueractioncodedenial',
    (0x9F, 0x0F): 'emv_9f0f_issueractioncodeonline',
    (0x9F, 0x10): 'emv_9f10_issuerapplicationdata',
    (0x9F, 0x11): 'emv_9f11_issuercodetableindex',
    (0x9F, 0x14): 'emv_9f14_lowerconsecutiveofflinelimit',
    (0x9F, 0x17): 'emv_9f17_personalidentificationnumbertrycounter',
    (0x9F, 0x1A): 'emv_9f1a_terminalcountrycode',
    (0x9F, 0x1E): 'emv_9f1e_interfacedeviceserialnumber',
    (0x9F, 0x21): 'emv_9f21_transactiontime',
    (0x9F, 0x24): 'emv_9f24_par',
    (0x9F, 0x26): 'emv_9f26_applicationcryptogram',
    (0x9F, 0x27): 'emv_9f27_cryptograminformationdata',
    (0x9F, 0x33): 'emv_9f33_terminalcapabilities',
    (0x9F, 0x34): 'emv_9f34_cardholderverificationmethodresults',
    (0x9F, 0x35): 'emv_9f35_terminaltype',
    (0x9F, 0x36): 'emv_9f36_applicationtransactioncounter',
    (0x9F, 0x37): 'emv_9f37_unpredictablenumber',
    (0x9F, 0x39): 'emv_9f39_posentrymode',
    (0x9F, 0x40): 'emv_9f40_additionalterminalcapabilities',
    (0x9F, 0x41): 'emv_9f41_transactionsequencecounter',
    (0x9F, 0x4C): 'emv_9f4c_iccdynamicnum',
    (0x9F, 0x53): 'emv_9f53_transactioncategorycode',
    (0x9F, 0x5B): 'emv_9f5b_issuerscriptresults',
    (0x9F, 0x6E): 'emv_9f6e_thirdpartydata',
    (0x9F, 0x7C): 'emv_9f7c_merchantcustomdata',
    # ( 0x9F, 0x66 ) : 'emv_9f66_ttq',
    # emv_kernel_version
    # emv_fallback
    # emv_fallback_type
    (0xDF, 0xDF, 0x06): 'emv_tac_default',
    (0xDF, 0xDF, 0x07): 'emv_tac_online',
    (0xDF, 0xDF, 0x08): 'emv_tac_denial'
}

# EMV tags to map to TCLink as ASCII data
EMV_TAG_ASCII_MAP = {
    (0x50, ): 'emv_50_applicationlabel',
    (0x5F, 0x20): 'name',
    # 20201110: FDRC analyst requests not to send this tag
    # ( 0x8A, ) : 'emv_8a_authorizationresponsecode',
    (0x9F, 0x12): 'emv_9f12_applicationpreferredname',
    (0x9F, 0x1E): 'emv_9f1e_interfacedeviceserialnumber',
    (0x9F, 0x6B): 'emv_9f6b_track2mc'
}

AID_TAGS = [
    (0x4F, ),
    (0x84, ),
    (0x9F, 0x06)
]

# Based on John Luong's Vault Javascript (see attachment to US 9334)
# Note: Discover AID missing from default creditAidList is likely a bug; check with John L.
AID_LISTS = {
    'default': {
        'cashbackAidList': [
            b'A0000001523010',       # Discover
            b'A0000000042203',       # MasterCard U.S. Maestro common debit
            b'A0000000980840',       # Visa common debit
            b'A0000000043060'        # MasterCard International Maestro
        ],
        'debitAidList': [
            b'A0000000043060'        # MasterCard International Maestro
            b'A0000002771010'        # Interact
            b'A0000006200620'        # DNA US Common Debit
        ],
        'creditAidList': [
            b'A0000000041010',       # MasterCard Credit
            b'A0000000042203',       # MasterCard US Maestro
            b'A0000000980840'        # Visa Common Debit
        ],
        'masterCardAidList': [
            b'A0000000041010'        # MasterCard Credit
        ]
    },
    'vital': {
        'cashbackAidList': [
            b'A0000000043060',       # MasterCard International Maestro
            b'A0000000042203',       # MasterCard U.S. Maestro common debit
            b'A0000000980840',       # Visa common debit
            b'A0000000032010',       # Visa Electron
            b'A0000000033010'        # Visa Interlink
        ],
        'debitAidList': [
            b'A0000000043060',       # MasterCard International Maestro
            b'A0000000042203',       # MasterCard U.S. Maestro common debit
            b'A0000000980840',       # Visa common debit
            b'A0000000033010'        # Visa Interlink
        ],
        'creditAidList': [
            b'A00000002501',         # Amex
            b'A0000001523010',       # Diners
            b'A0000003241010',       # Discover
            b'A0000000651010',       # JCB
            b'A0000000041010',       # MasterCard Credit
            b'A0000000032010',       # Visa Electron
            b'A0000000031010'        # Visa Credit and Visa Debit International
        ],
        'masterCardAidList': [
            b'A0000000041010'        # MasterCard Credit
        ]
    },
    'paymentech-tandem': {
        'cashbackAidList': [
            b'A0000000043060',       # MasterCard International Maestro
            b'A0000000042203',       # MasterCard U.S. Maestro common debit
            b'A0000000980840',       # Visa common debit
            b'A0000001523010',       # Discover
        ],
        'debitAidList': [
            b'A0000000043060',       # MasterCard International Maestro
            b'A0000000042203',       # MasterCard U.S. Maestro common debit
            b'A0000000980840',       # Visa common debit
            b'A0000000033010',       # Visa Interlink.
            b'A0000001524010',       # Discover US Common Debit
            b'A0000006200620'        # DNA US Common Debit
        ],
        'creditAidList': [
            b'A00000002501',         # Amex
            b'A0000001523010',       # Diners
            b'A0000003241010',       # Discover
            b'A0000000651010',       # JCB
            b'A0000000041010',       # MasterCard Credit
            b'A0000000032010',       # Visa Electron
            b'A0000000031010'        # Visa Credit and Visa Debit International
        ],
        'masterCardAidList': [
            b'A0000000041010'        # MasterCard Credit
        ]
    },
    'firstdatarapidconnect': {
        'cashbackAidList': [
            b'A0000001523010',       # Discover
            b'A0000000042203',       # MasterCard U.S. Maestro common debit
            b'A0000000980840',       # Visa common debit
            b'A0000000043060'        # MasterCard International Maestro
        ],
        'debitAidList': [
            b'A0000000043060',       # MasterCard International Maestro
            b'A0000000033010'        # Visa Interlink Global Debit
            b'A0000006200620'        # DNA US Common Debit
            b'A0000002771010'        # Interact
        ],
        'creditAidList': [
            b'A00000002501',         # Amex
            b'A0000000041010',       # MasterCard Credit
            b'A0000000042203',       # MasterCard US Maestro
            b'A0000000980840',       # Visa Common Debit
            b'A0000000032010',       # Visa Electron
            b'A0000000031010'        # Visa Credit and Visa Debit International
        ],
        'masterCardAidList': [
            b'A0000000041010'        # MasterCard Credit
        ]
    },
    'elavon': {
        'cashbackAidList': [
            b'A0000000043060',       # MasterCard International Maestro
            b'A0000000042203',       # MasterCard U.S. Maestro common debit
            b'A0000000980840',       # Visa common debit
            b'A0000001523010'        # Discover
        ],
        'debitAidList': [
            b'A0000000043060',       # MasterCard International Maestro
            b'A0000000042203',       # MasterCard U.S. Maestro common debit
            b'A0000000980840',       # Visa common debit
            b'A0000000033010',       # Visa Interlink.
            b'A0000001524010',       # Discover US Common Debit
            b'A0000006200620'        # DNA US Common Debit
        ],
        'creditAidList': [
            b'A00000002501',         # Amex
            b'A0000001523010',       # Diners
            b'A0000003241010',       # Discover
            b'A0000000651010',       # JCB
            b'A0000000041010',       # MasterCard Credit
            b'A0000000032010',       # Visa Electron
            b'A0000000031010'        # Visa Credit and Visa Debit International

        ],
        'masterCardAidList': [
            b'A0000000041010'        # MasterCard Credit
        ]
    }
}


def setDeviceSerial(deviceSerial):
    global DEVICE_SERIAL
    DEVICE_SERIAL = deviceSerial


def setDeviceUnattendedMode(deviceMode):
    global DEVICE_UNATTENDED
    DEVICE_UNATTENDED = deviceMode


def setDeviceFallbackMode(fallbackType):
    global IS_FALLBACK, FALLBACK_TYPE
    IS_FALLBACK = 'y'
    FALLBACK_TYPE = fallbackType

# Pad TLV data with fake Status bytes that are expected by TLVPrepare().parse_received_data()
def padTLVData(tlv_data):
    tlv_data_padded = bytearray(len(tlv_data))
    tlv_data_padded[:] = tlv_data
    tlv_data_padded.extend(b'\x90\x00')
    return tlv_data_padded

# Capture/update encrypted track values
def saveCardData(tlv):
    global LOG_INTERNAL_DATA, LOG
    global ENCRYPTED_TRACK_IV, ENCRYPTED_TRACK_KSN, ENCRYPTED_TRACK_DATA
    if LOG_INTERNAL_DATA:
        with open("saveCardData" + datetime.now().strftime("%Y-%m-%d-%H-%M-%S-%f") + ".pickle", 'wb') as f:
            pickle.dump(tlv, f)
    #print(">>> saveCardData ff7f count", tlv.tagCount((0xFF,0x7F)))
    if tlv.tagCount((0xFF, 0x7F)) and len(tlv.getTag((0xFF, 0x7F))[0]) > 8:
        vsp_tlv_data_padded = padTLVData(tlv.getTag((0xFF, 0x7F))[0])
        #LOG.log('>>> vsp_tlv bytes', tlv.getTag((0xFF,0x7F))[0], 'padded to', vsp_tlv_data_padded)
        tlvp = TLVPrepare()
        vsp_tlv_tags = tlvp.parse_received_data(vsp_tlv_data_padded)
        vsp_tlv = TLVParser(vsp_tlv_tags)
        #vsp_tlv = TLVParser(tlv.getTag((0xFF,0x7F))[0])
        #LOG.log('>>> buf', buf)
        #LOG.log('>>> tlv', tlv)
        #LOG.log('>>> vsp_tlv_tags', vsp_tlv_tags)
        #LOG.log('>>> vsp_tlv', vsp_tlv)
        # if vsp_tlv.tagCount((0xDF,0xDF,0x10)):
        #	print(">>> saveCardData vsp_tlv DFDF10", hexlify(vsp_tlv.getTag((0xDF,0xDF,0x10))[0]))
        # if vsp_tlv.tagCount((0xDF,0xDF,0x11)):
        #	print(">>> saveCardData vsp_tlv DFDF11", hexlify(vsp_tlv.getTag((0xDF,0xDF,0x11))[0]))
        # if vsp_tlv.tagCount((0xDF,0xDF,0x12)):
        #	print(">>> saveCardData vsp_tlv DFDF12", hexlify(vsp_tlv.getTag((0xDF,0xDF,0x12))[0]))
        if vsp_tlv.tagCount((0xDF, 0xDF, 0x10)) and vsp_tlv.tagCount((0xDF, 0xDF, 0x11)) and vsp_tlv.tagCount((0xDF, 0xDF, 0x12)):
            print(">>> saveCardData save data")
            ENCRYPTED_TRACK_IV = vsp_tlv.getTag(
                (0xDF, 0xDF, 0x12))[0].hex().upper()
            ENCRYPTED_TRACK_KSN = vsp_tlv.getTag(
                (0xDF, 0xDF, 0x11))[0].hex().upper()
            ENCRYPTED_TRACK_DATA = vsp_tlv.getTag(
                (0xDF, 0xDF, 0x10))[0].hex().upper()

# Capture/update EMV data values
def saveEMVData(tlv, template):
    global LOG_INTERNAL_DATA, LOG
    global EMV_TAGS, POS_ENTRY_MODE, EMV_PROCESSING_CODE
    global PLATFORM, AID_TAGS, AID_LISTS
    #print("saveEMVData", str(template))
    processingcode = 'credit'
    if LOG_INTERNAL_DATA:
        with open("saveEMVData-" + hex(template) + "-" + datetime.now().strftime("%Y-%m-%d-%H-%M-%S-%f") + ".pickle", 'wb') as f:
            pickle.dump(tlv, f)
    #print(">>> saveEMVData: template", hex(template), "count", tlv.tagCount((template)))
    if tlv.tagCount((template)):
        tags = tlv.getTag((template))
        #print('>>> tags', str(tags))
        for tag in tags:
            #EMV_TAGS[tag[0]] = tag[1]
            #print(">>  tag", tag[0], "value", tag[1])
            if tag[0] == (0x9F, 0x39):  # POS Entry Mode
                # CLess EMV (07) or CLess Magstrip (91)
                if tag[1] == b'\x07' or tag[1] == b'\x91':
                    #print(">> POS Mode", tag[1])
                    POS_ENTRY_MODE = 'contactless=y'
            if tag[0] == (0xBF, 0x0C):
                try:
                    fci_data_padded = padTLVData(tag[1])
                    #print(">>  EMV FCI found", str(tag[1]), "padded to", fci_data_padded)
                    tlvp = TLVPrepare()
                    fci_tlv_tags = tlvp.parse_received_data(fci_data_padded)
                    #print(">>    FCI tlv tags", str(fci_tlv_tags))
                    fci_tlv = TLVParser(fci_tlv_tags)
                    #print(">>    FCI tags", str(fci_tlv))
                    if fci_tlv.tagCount((0x5F, 0x55)) and fci_tlv.getTag((0x5F, 0x55))[0].decode('utf-8') == "US" and fci_tlv.tagCount((0x42)):
                        #print(">>    FCI ICC tag", fci_tlv.getTag((0x5F,0x55))[0].decode('utf-8'))
                        #print(">>    FCI IIN tag", fci_tlv.getTag((0x42))[0].hex().upper())
                        #print(">>    US Common Debit")
                        processingcode = 'debit'
                except:
                    pass
            emv_processing_code = 'credit'
            try:
                if tag[0] in AID_TAGS:
                    aid_value = hexlify(tag[1]).upper()
                    print(">> AID is ", aid_value)

                    # TAG 84: Application Identifier
                    saveEMVHEXMapTag(
                        ((0x84, ), aid_value.decode('utf-8').upper()), False)

                    platform = PLATFORM
                    if platform not in AID_LISTS.keys():
                        platform = 'default'
                    #print(">>   Found", str(tag[0]), "in AID_TAGS with value", aid_value, "with platform", platform)
                    for debit_aid in AID_LISTS[platform]['debitAidList']:
                        if debit_aid == aid_value:
                            emv_processing_code = 'debit'
                            break
                        #print("debit_aid", str(debit_aid), "no match for aid_value", str(aid_value))
                    for credit_aid in AID_LISTS[platform]['creditAidList']:
                        if credit_aid == aid_value:
                            emv_processing_code = 'credit'
                            break
                        #print("credit_aid", str(credit_aid), "no match for aid_value", str(aid_value))
                    print(">> processing code", emv_processing_code)
                    if len(emv_processing_code) > 0:
                        EMV_PROCESSING_CODE = emv_processing_code
            except Exception as e:
                #print(">>  Exception looking for AIDs", print(e))
                pass
            try:
                EMV_TAGS[EMV_TAG_ASCII_MAP[tag[0]]] = tag[1].decode('utf-8')
                #print(">>  EMV_TAGS now ", str(EMV_TAGS))
                #print(">>  EMV_TAGS added ASCII ", EMV_TAG_ASCII_MAP[tag[0]], "=", EMV_TAGS[EMV_TAG_ASCII_MAP[tag[0]]])
            except:
                try:
                    EMV_TAGS[EMV_TAGS_HEX_MAP[tag[0]]] = tag[1].hex().upper()
                    #print(">>  EMV_TAGS now ", str(EMV_TAGS))
                    #print(">>  EMV_TAGS added hex ", EMV_TAGS_HEX_MAP[tag[0]], "=", EMV_TAGS[EMV_TAGS_HEX_MAP[tag[0]]])
                except:
                    LOG.log(">>  EMV_TAGS skipped ", hexlify(
                        bytearray(tag[0])), "=", hexlify(tag[1]))
                    pass
    return processingcode


def saveEMVASCIITag(tag):
    global EMV_TAGS, EMV_TAG_ASCII_MAP, EMV_TAGS_HEX_MAP
    try:
        if tag[0] in EMV_TAG_ASCII_MAP.keys():
            EMV_TAGS[EMV_TAG_ASCII_MAP[tag[0]]] = tag[1].decode('utf-8')
            #print(">>  EMV_TAGS now ", str(EMV_TAGS))
            #print(">>  EMV_TAGS added ASCII ", EMV_TAG_ASCII_MAP[tag[0]], "=", EMV_TAGS[EMV_TAG_ASCII_MAP[tag[0]]])
    except (KeyError):
        LOG.log(">>  EMV_TAGS skipped ", hexlify(
            bytearray(tag[0])), "=", hexlify(tag[1]))
        pass


def saveEMVHEXMapTag(tag, hexConversion=True):
    global EMV_TAGS, EMV_TAG_ASCII_MAP, EMV_TAGS_HEX_MAP
    try:
        if tag[0] in EMV_TAGS_HEX_MAP.keys():
            EMV_TAGS[EMV_TAGS_HEX_MAP[tag[0]]] = tag[1].hex(
            ).upper() if hexConversion else tag[1]
    except (KeyError):
        LOG.log(">>  EMV_TAGS skipped ", hexlify(
            bytearray(tag[0])), "=", hexlify(tag[1]))
        pass

def saveMSRTrack2AndExpiry(track2, expiry):
    global MSR_TRACK2_DATA, MSR_EXPIRY_DATA
    
    MSR_TRACK2_DATA = track2
    MSR_EXPIRY_DATA = expiry
    

def printEMVHexTags():
    print(">>  EMV_TAGS now ", str(EMV_TAGS))


def SetProperties(args, log):
    global LOG_INTERNAL_DATA, LOG, DEVICE_PINPAD_CAPABLE, PARTIAL_AUTH, ISBALANCEINQUIRY, CASHBACK_AMOUNT

    if args.action == 'verify':
        ISBALANCEINQUIRY = True
    else:
        PARTIAL_AUTH = str(args.partialauth)

    if args.cashback != None and len(args.cashback):
        tclink.PushNameValue("cashback="+str(args.cashback))
        
    DEVICE_PINPAD_CAPABLE = str(args.device_pinpad_capable)

    LOG = log
    if LOG_INTERNAL_DATA:
        with open("SetProperties" + datetime.now().strftime("%Y-%m-%d-%H-%M-%S-%f") + ".pickle", 'wb') as f:
            pickle.dump(args, f)
    try:
        tclink.PushNameValue("custid="+str(args.custid))
    except:
        pass
    try:
        tclink.PushNameValue("password="+args.password)
    except:
        pass
    try:
        tclink.PushNameValue("action="+args.action)
        if args.action == 'verify':
            tclink.PushNameValue("balance=y")
    except:
        pass
    try:
        if ISBALANCEINQUIRY == False:
            tclink.PushNameValue("amount="+str(args.amount))
    except:
        pass
    try:
        tclink.PushNameValue("operator="+args.operator)
    except:
        pass
    try:
        tclink.PushNameValue("lanenumber="+args.lanenumber)
    except:
        pass


def showTCLinkResponse():
    status = 'unknown'
    try:
        status = tclink.GetResponse("status")
    except:
        pass
    print("Status:", status)

    try:
        print("TransID:", tclink.GetResponse("transid"))
    except:
        pass
    try:
        print("AuthCode:", tclink.GetResponse("authcode"))
    except:
        pass
    try:
        print("TSI:", EMV_TAGS['emv_9b_transactionstatusinformation'])
    except:
        pass
    return status


def getDeclineType():
    declinetype = "unknown"
    try:
        declinetype = tclink.GetResponse("declinetype")
    except:
        pass
    print("DECLINE-TYPE:", declinetype)
    return declinetype


def addEMVTagData():
    global EMV_TAGS, POS_ENTRY_MODE, EMV_PROCESSING_CODE, DEVICE_PINPAD_CAPABLE, PARTIAL_AUTH, ISBALANCEINQUIRY

    # override section
    #aid = EMV_TAGS.get("emv_4f_applicationidentifiericc")
    datestr = str(datetime.today().year)[
        2:] + str(datetime.today().month).zfill(2) + str(datetime.today().day).zfill(2)
    timestr = str(datetime.today().hour).zfill(
        2) + str(datetime.today().minute).zfill(2) + str(datetime.today().second).zfill(2)
    OVERRIDE_TAGS = {
        # "requested_action" : "sale",  # commented out tags debugging revealed not needed to send
        # "emv_84_dedicatedfilename" : aid,
        # "emv_82_applicationinterchangeprofile" : "1C00",
        # "emv_9f1e_interfacedeviceserialnumber" : "SC010460",
        # "emv_9f40_additionalterminalcapabilities" : "F000F0A001",
        # "emv_9f41_transactionsequencecounter" : "00000007",
        # "emv_8a_authorizationresponsecode" : "00", # 0xDE, 0xD2 continue command sends this tag
        # "emv_processingcode" : "credit",
        "emv_9f53_transactioncategorycode": "52",
        "emv_kernel_version": "0488",   # TSYS
        "emv_9f1a_terminalcountrycode": "0840",
        # send date and time to avoid Do Not Honor decline
        "emv_9f21_transactiontime": timestr,
        "emv_9a_transactiondate": datestr,
        "device_pinpad_capable": DEVICE_PINPAD_CAPABLE
    }

    if ISBALANCEINQUIRY == False:
        OVERRIDE_TAGS["partialauth"] = PARTIAL_AUTH

    print("Override tags used:")
    for tag, data in OVERRIDE_TAGS.items():
        if tag != "":
            olddata = "<none>"
            try:
                olddata = EMV_TAGS[tag]
            except:
                pass
            EMV_TAGS[tag] = data
            print("  ", tag, "Prior value was:",
                  olddata, " New value is:", data)

    print("End override tags")
    # end override section

    if len(POS_ENTRY_MODE) > 0:
        tclink.PushNameValue(POS_ENTRY_MODE)
    if len(EMV_TAGS) > 0:
        if ISBALANCEINQUIRY == False:
            tclink.PushNameValue("quickchip=y")
        tclink.PushNameValue("emv_processingcode=" + EMV_PROCESSING_CODE)

        for tag, data in EMV_TAGS.items():
            tclink.PushNameValue(tag + "=" + data)


def processMSRTransaction():
    global DEVICE_SERIAL, DEVICE_UNATTENDED, ENCRYPTED_TRACK_IV, ENCRYPTED_TRACK_KSN, ENCRYPTED_TRACK_DATA
    global IS_FALLBACK, FALLBACK_TYPE, MSR_TRACK2_DATA, MSR_EXPIRY_DATA
    
    print(">>> processMSRTransaction iv", ENCRYPTED_TRACK_IV)
    # NOTE: John L. noted we should not send 'emv_processingcode=credit' for fallback
    tclink.PushNameValue("emv_device_capable=y")
    tclink.PushNameValue("encryptedtrack="+"TVP|iv:"+ENCRYPTED_TRACK_IV +
                         "|ksn:"+ENCRYPTED_TRACK_KSN+"|vipa:"+ENCRYPTED_TRACK_DATA)
    tclink.PushNameValue("aggregators=1")
    tclink.PushNameValue("aggregator1=L9XPR6")
    tclink.PushNameValue("device_serial="+DEVICE_SERIAL)
    tclink.PushNameValue("unattended="+DEVICE_UNATTENDED)
    if IS_FALLBACK == 'y':
        tclink.PushNameValue("emv_fallback=y")
        tclink.PushNameValue("emv_fallback_type="+FALLBACK_TYPE)
	#TODO: add in next test iteration
    #if len(MSR_TRACK2_DATA) and len(MSR_EXPIRY_DATA):
    #    tclink.PushNameValue("track2="+MSR_TRACK2_DATA)
    #    tclink.PushNameValue("exp="+MSR_EXPIRY_DATA)
        
    # print("encryptedtrack="+"TVP|iv:"+ENCRYPTED_TRACK_IV+"|ksn:"+ENCRYPTED_TRACK_KSN+"|vipa:"+ENCRYPTED_TRACK_DATA)
    tclink.Submit()
    return showTCLinkResponse()


def processCLessMagstripeTransaction():
    global DEVICE_SERIAL, DEVICE_UNATTENDED, ENCRYPTED_TRACK_IV, ENCRYPTED_TRACK_KSN, ENCRYPTED_TRACK_DATA, EMV_TAGS
    #print(">>> processCLessMagstripTransaction iv", ENCRYPTED_TRACK_IV)
    # TODO: should we add 'emv_processingcode=...' when we do CLess Magstrip (and what value would it used; credit, debit or blank/empty)?
    tclink.PushNameValue("emv_device_capable=y")
    tclink.PushNameValue("contactless=y")
    tclink.PushNameValue("encryptedtrack="+"TVP|iv:"+ENCRYPTED_TRACK_IV +
                         "|ksn:"+ENCRYPTED_TRACK_KSN+"|vipa:"+ENCRYPTED_TRACK_DATA)
    tclink.PushNameValue("aggregators=1")
    tclink.PushNameValue("aggregator1=L9XPR6")
    tclink.PushNameValue("device_serial="+DEVICE_SERIAL)
    tclink.PushNameValue("unattended="+DEVICE_UNATTENDED)
    print(">> ClessMagstripe: len(EMV_TAGS)", str(len(EMV_TAGS)))
    addEMVTagData()
    # print("encryptedtrack="+"TVP|iv:"+ENCRYPTED_TRACK_IV+"|ksn:"+ENCRYPTED_TRACK_KSN+"|vipa:"+ENCRYPTED_TRACK_DATA)
    #print(">> EMV_TAGS", str(EMV_TAGS))
    tclink.Submit()
    return showTCLinkResponse()


def processEMVTransaction():
    global DEVICE_SERIAL, DEVICE_UNATTENDED, ENCRYPTED_TRACK_IV, ENCRYPTED_TRACK_KSN, ENCRYPTED_TRACK_DATA, EMV_TAGS
    #print(">>> processEMVTransaction iv", ENCRYPTED_TRACK_IV)
    # tclink.PushNameValue("_transid_override=100-1000010001")
    tclink.PushNameValue("emv_device_capable=y")
    tclink.PushNameValue("encryptedtrack="+"TVP|iv:"+ENCRYPTED_TRACK_IV +
                         "|ksn:"+ENCRYPTED_TRACK_KSN+"|vipa:"+ENCRYPTED_TRACK_DATA)
    tclink.PushNameValue("aggregators=1")
    tclink.PushNameValue("aggregator1=L9XPR6")
    tclink.PushNameValue("device_serial="+DEVICE_SERIAL)
    tclink.PushNameValue("unattended="+DEVICE_UNATTENDED)
    print(">> EMV: len(EMV_TAGS)", str(len(EMV_TAGS)))
    addEMVTagData()
    # print("encryptedtrack="+"TVP|iv:"+ENCRYPTED_TRACK_IV+"|ksn:"+ENCRYPTED_TRACK_KSN+"|vipa:"+ENCRYPTED_TRACK_DATA)
    #Sprint(">> EMV_TAGS", str(EMV_TAGS))
    tclink.Submit()
    return showTCLinkResponse()


def processPINTransaction(encryptedPIN, ksn):
    global DEVICE_SERIAL, DEVICE_UNATTENDED, ENCRYPTED_TRACK_IV, ENCRYPTED_TRACK_KSN, ENCRYPTED_TRACK_DATA, EMV_TAGS
    print("Encrypted pin/ksn", encryptedPIN, ksn)
    tclink.PushNameValue("pin=" + encryptedPIN + ksn)
    tclink.PushNameValue("emv_device_capable=y")
    tclink.PushNameValue("encryptedtrack="+"TVP|iv:"+ENCRYPTED_TRACK_IV +
                         "|ksn:"+ENCRYPTED_TRACK_KSN+"|vipa:"+ENCRYPTED_TRACK_DATA)
    tclink.PushNameValue("aggregators=1")
    tclink.PushNameValue("aggregator1=L9XPR6")
    tclink.PushNameValue("device_serial="+DEVICE_SERIAL)
    tclink.PushNameValue("unattended="+DEVICE_UNATTENDED)
    print(">> EMV: len(EMV_TAGS)", str(len(EMV_TAGS)))
    addEMVTagData()
    tclink.Submit()
    return showTCLinkResponse()
