import urllib2
import uuid
from datetime import datetime, timedelta
from hashlib import md5
from threading import Lock
from urllib import quote_plus, urlencode

from plone.memoize import ram
from plone.event.interfaces import IEventAccessor
from AccessControl.SecurityManagement import getSecurityManager
from zExceptions import Unauthorized

# global defaults and definitions:
BASE_URL = "http://maps.google.com/maps/api/staticmap"
NS_UPIQ = uuid.uuid3(uuid.NAMESPACE_DNS, 'upiq.org')
IMAGE_MIME = 'image/png'
DEFAULT_LOC = '295 Chipeta Way, Salt Lake City, UT'
DEFAULT_SIZE = (500,500) #width, height
DEFAULT_ZOOM = 15 #google maps zoom level
DEFAULT_UID = uuid.uuid3(NS_UPIQ, 'StaticMapView')

# empty 1x1 pizel transparent png:
ONE_PX_PNG = '\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x01\x03\x00\x00\x00%\xdbV\xca\x00\x00\x00\x03PLTE\x00\x00\x00\xa7z=\xda\x00\x00\x00\x01tRNS\x00@\xe6\xd8f\x00\x00\x00\nIDAT\x08\xd7c`\x00\x00\x00\x02\x00\x01\xe2!\xbc3\x00\x00\x00\x00IEND\xaeB`\x82'

def make_map_qs(loc, zoom, size):
    """URL query string template function for Google Static Maps API"""
    zoom = int(zoom) #validate
    size = (int(size[0]), int(size[1])) #(w,h)
    q = {   'markers'   : '|'.join(['color:blue', loc]), 
            'zoom'      : zoom,
            'size'      : '%sx%s' % size,
            'sensor'    : 'false',
            'maptype'   : 'roadmap',
        }
    return urlencode(q)


# mapping signature string key
msignature = lambda d: md5(str(hash(tuple(sorted(d.items()))))).hexdigest()

#utility functions related to caching
dottedname = lambda cls: '%s.%s' % (cls.__module__, cls.__name__)
query_key = lambda query: ('StaticMapView', msignature(query))
cache_key = lambda obj, fn, query: query_key(query)

# track cache timestamps for expiration, invalidation of memoized result
timestamps = {} #key is query signature md5 hash, value is timestamp
writelock = Lock() #mutex for timestamps modification


class StaticMapView(object):
    """
    View gets, returns PNG image data proxied to Google Static Maps API.
    Note: this doesn't implement internal checks on abuse; a view permission
    in ZCML can however restrict this to 
    """
    
    def __init__(self, context, request):
        self.context = context
        self.request = request

    def check_abuse(self):
        user = getSecurityManager().getUser()
        roles = user.getRolesInContext(self.context)
        if 'Authenticated' in roles:
            return # authenticated user, trust implicitly
        
        #TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO
        return #TODO: don't bypass anonymous validation: TODO TODO TODO TODO
        
        #tricky, not perfect, but require client to pass UID of the context:
        req_uid = self.request.get('uid', '').strip()
        if not req_uid:
            self.request.response.setStatus(403)
            raise
        context_uid = str(DEFAULT_UID)
        if hasattr(self.context, 'UID'):
            context_uid = self.context.UID()
        if not req_uid.strip() == context_uid.strip():
            self.request.response.setStatus(403)
            raise
    
    @ram.cache(cache_key)
    def getmap(self, query):
        """
        Get static map image data from Google Maps (memoized using ram
        cache); returns raw png data retrieved via urllib2 for query.
        Query should be a dict with three keys: 'loc' (a string),
        'size' (a tuple of integers), and 'zoom' (an integer zoom level).
        """
        global timestamps, writelock
        url = '%s?%s' % (BASE_URL, make_map_qs(**query))
        request = urllib2.Request(url)
        handler = urllib2.build_opener()
        image_data = handler.open(url).read()
        writelock.acquire()
        timestamps[query_key(query)] = datetime.now()
        writelock.release()
        return image_data
    
    def _set_headers(self, modified, expires, size, content_type='image/png'):
        dfmt = lambda dt: dt.strftime('%a, %d %b %Y %H:%M:%S')
        resp = self.request.response
        resp.setHeader('Content-type', content_type)
        resp.setHeader('Content-length', str(size))
        resp.setHeader('Last-Modified', dfmt(modified))
        resp.setHeader('Expires', dfmt(expires))
    
    def _purge_cached(self, query):
        global timestamps, writelock
        writelock.acquire()
        key = query_key(query)
        if key in timestamps:
            del(timestamps[key])
        writelock.release()
        ram.global_cache.invalidate(
            '.'.join((dottedname(self.__class__), 'getmap')),
            key=cache_key(None, None, query),
            )
    
    def __call__(self):
        global timestamps
        self.check_abuse()
        req = self.request
        w,h = DEFAULT_SIZE
        query = {
            'loc'   : req.get('loc', DEFAULT_LOC),
            'size'  : (req.get('width', w), req.get('height', h)),
            'zoom'  : int(req.get('zoom', DEFAULT_ZOOM)), }
        now = datetime.now()
        modified = timestamps.get(msignature(query), None) or now
        expires = modified + timedelta(days=1)
        if expires < now:
            self._purge_cached(query)
        data = self.getmap(query)
        #TODO: some cache expiration purge the memoization after 24 hours
        self._set_headers(modified, expires, bytes)
        return data


class EventMapView(object):
    def __init__(self, context, request):
        self.context = context
        self.request = request
        self.has_loc = False
        self.load_loc()
    
    def load_loc(self):
        context = self.context
        if hasattr(context, 'getLocation') and context.getLocation():
            request['loc'] = context.getLocation().strip()
            self.has_loc = True

    def map_link(self):
        base = "http://maps.google.com/maps?q="
        return "%s%s" % (base, quote_plus(self.request.get('loc','').strip()))
    
    def __call__(self):
         if self.has_loc:
            staticmap = StaticMapView(self.context, self.request)
            return staticmap()
         #otherwise, default to 1 px transparent PNG:
         resp.setHeader('Content-type', 'image/png')
         return ONE_PX_PNG


class PAEEventMapView(EventMapView):

    def load_loc(self):
        context = self.context
        loc = IEventAccessor(context).location
        if loc:
            self.request['loc'] = loc.strip()
            self.has_loc = True

