# vBulletin
L_HOOKS = dict()
L_HOOKS['url'] = 'login.php\?do=login'
L_HOOKS['module'] = 'vbulletin.parsevBulletin'

def parsevBulletin(Headers, ipsrc='', hook=''):
    import re
    User = re.findall("(?i)vb_login_username=([A-Za-z0-9_-]+)&(.*)", Headers['body'])

    if len(User) > 0:
       if len(User[0]) > 0:
           return "[BOARDS]: site="+str(Headers['headers']['host'][0])+", body="+Headers['body']+", ip="+str(ipsrc)
