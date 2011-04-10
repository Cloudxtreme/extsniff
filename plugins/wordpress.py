# vBulletin
L_HOOKS = dict()
L_HOOKS['url'] = 'wp-login.php'
L_HOOKS['module'] = 'wordpress.parseWordpress'

def parseWordpress(Headers, ipsrc='', hook=''):
    import re
    User = re.findall("(?i)log=([A-Za-z0-9_-]+)&(.*)", Headers['body'])
    Passwd = re.findall("(?i)pwd=([A-Za-z0-9_-]+)&(.*)", Headers['body'])

    if len(User) > 0 and len(Passwd) > 0:
       if len(User[0]) > 0 and len(Passwd[0]) > 0:
           return "[WORDPRESS]: site="+str(Headers['headers']['host'][0])+", user="+str(User[0][0])+", passwd="+Passwd[0][0]+", ip="+str(ipsrc)
