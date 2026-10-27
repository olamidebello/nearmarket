"""Private trade origins, tenant radius policies and server-side distance checks."""
import hashlib,json,math,os,re,time,urllib.request
import gateway_admin

MI_TO_KM=1.609344
DEFAULT_RADIUS_KM=60*MI_TO_KM

def init(c):
    c.executescript('''
    CREATE TABLE IF NOT EXISTS location_policies(tenant_id INTEGER PRIMARY KEY REFERENCES tenants(id),default_buy_km REAL DEFAULT 96.56064,default_sell_km REAL DEFAULT 96.56064,max_buy_km REAL DEFAULT 500,max_sell_km REAL DEFAULT 500,center_lat REAL,center_lon REAL,area_label TEXT DEFAULT '',market_radius_km REAL DEFAULT 50,restrict_marketplace INTEGER DEFAULT 0);
    CREATE TABLE IF NOT EXISTS trade_locations(tenant_id INTEGER REFERENCES tenants(id),user_id INTEGER REFERENCES users(id),kind TEXT,lat REAL,lon REAL,radius_km REAL,label TEXT,unit TEXT DEFAULT 'mi',locked INTEGER DEFAULT 0,PRIMARY KEY(tenant_id,user_id,kind));
    CREATE TABLE IF NOT EXISTS listing_locations(listing_id INTEGER PRIMARY KEY REFERENCES listings(id),lat REAL,lon REAL,radius_km REAL,label TEXT DEFAULT '');
    CREATE TABLE IF NOT EXISTS geocode_rate(user_id INTEGER PRIMARY KEY,window INTEGER,count INTEGER);
    CREATE TABLE IF NOT EXISTS geocode_cache(user_id INTEGER,tenant_id INTEGER,query_hash TEXT,response TEXT,created REAL,PRIMARY KEY(user_id,tenant_id,query_hash));
    ''')
    columns={r[1] for r in c.execute('PRAGMA table_info(trade_locations)')}
    if 'use_current' not in columns:c.execute('ALTER TABLE trade_locations ADD COLUMN use_current INTEGER DEFAULT 1')

def number(value,minimum,maximum,message):
    try:n=float(value)
    except (ValueError,TypeError):raise ValueError(message) from None
    if not math.isfinite(n) or not minimum<=n<=maximum:raise ValueError(message)
    return n

def point(lat,lon):
    return number(lat,-90,90,'Enter a latitude from -90 to 90'),number(lon,-180,180,'Enter a longitude from -180 to 180')

def radius(value,unit='km',maximum=10000):
    if unit not in ('km','mi'):raise ValueError('Select km or miles')
    km=number(value,0.000001,10000,'Enter a positive radius')*(MI_TO_KM if unit=='mi' else 1)
    if not 0.1<=km<=maximum:raise ValueError(f'Radius must be between 0.1 and {maximum:g} km')
    return km

def distance(a,b,x,y):
    p,q=math.radians(a),math.radians(x)
    v=math.sin((q-p)/2)**2+math.cos(p)*math.cos(q)*math.sin(math.radians(y-b)/2)**2
    return 6371*2*math.asin(math.sqrt(min(1,max(0,v))))

def policy(c,tid):
    row=c.execute('SELECT * FROM location_policies WHERE tenant_id=?',(tid,)).fetchone()
    return dict(row) if row else dict(tenant_id=tid,default_buy_km=DEFAULT_RADIUS_KM,default_sell_km=DEFAULT_RADIUS_KM,max_buy_km=500,max_sell_km=500,center_lat=None,center_lon=None,area_label='',market_radius_km=50,restrict_marketplace=0)

def profile(c,tid,uid,kind):
    return c.execute('SELECT * FROM trade_locations WHERE tenant_id=? AND user_id=? AND kind=?',(tid,uid,kind)).fetchone() if uid else None

def in_market(p,lat,lon):
    return not p['restrict_marketplace'] or distance(p['center_lat'],p['center_lon'],lat,lon)<=p['market_radius_km']

def origin(c,t,u,q):
    p=policy(c,t['id']);saved=profile(c,t['id'],u['id'] if u else None,'buy')
    get=lambda name: q.get(name,[None])[0]
    if get('lat') is not None or get('lon') is not None:
        lat,lon=point(get('lat'),get('lon'))
    elif saved and not saved['use_current']:lat,lon=saved['lat'],saved['lon']
    elif p['center_lat'] is not None:lat,lon=p['center_lat'],p['center_lon']
    else:lat=lon=None
    km=radius(get('radius') if get('radius') is not None else (min(saved['radius_km'],p['max_buy_km']) if saved else p['default_buy_km']),(get('unit') or 'km') if get('radius') is not None else 'km',p['max_buy_km'])
    if saved and saved['locked']:
        if not saved['use_current']:lat,lon=saved['lat'],saved['lon']
        km=min(saved['radius_km'],p['max_buy_km'])
    return p,lat,lon,km

def rule(c,l,p):
    r=c.execute('SELECT * FROM listing_locations WHERE listing_id=?',(l['id'],)).fetchone()
    return dict(lat=r['lat'] if r else l['lat'],lon=r['lon'] if r else l['lon'],radius_km=min(r['radius_km'] if r else p['default_sell_km'],p['max_sell_km']))

def save_listing(c,t,seller,lid,d):
    p=policy(c,t['id']);saved=profile(c,t['id'],seller,'sell')
    lat,lon=point(d.get('lat'),d.get('lon'))
    old=c.execute('SELECT * FROM listing_locations WHERE listing_id=?',(lid,)).fetchone()
    km=radius(d.get('sell_radius',old['radius_km'] if old else saved['radius_km'] if saved else p['default_sell_km']),d.get('sell_radius_unit','km') if 'sell_radius' in d else 'km',p['max_sell_km'])
    if saved and saved['locked']:
        if not saved['use_current']:lat,lon=saved['lat'],saved['lon']
        km=min(saved['radius_km'],p['max_sell_km'])
    if not in_market(p,lat,lon):raise ValueError('The item location is outside this marketplace’s allowed area')
    label=str(d.get('private_address',old['label'] if old else '')).strip()
    if len(label)>300:raise ValueError('Private address is limited to 300 characters')
    c.execute('INSERT INTO listing_locations VALUES(?,?,?,?,?) ON CONFLICT(listing_id) DO UPDATE SET lat=excluded.lat,lon=excluded.lon,radius_km=excluded.radius_km,label=excluded.label',(lid,lat,lon,km,label))
    c.execute('UPDATE listings SET lat=?,lon=? WHERE id=?',(round(lat,2),round(lon,2),lid))

def decorate(c,l,p,lat,lon,km,own=False):
    r=rule(c,l,p);l=dict(l)
    exact=distance(lat,lon,r['lat'],r['lon']) if lat is not None else None
    eligible=exact is not None and exact<=km and exact<=r['radius_km'] and in_market(p,lat,lon) and in_market(p,r['lat'],r['lon'])
    if not own and (lat is None or not eligible):return None
    if not own and not in_market(p,r['lat'],r['lon']):return None
    l.update(distance=round(exact,1) if exact is not None else None,sell_radius_km=r['radius_km'],can_buy=eligible,requires_location=lat is None)
    return l

def require_purchase(c,t,u,l,d):
    saved=profile(c,t['id'],u['id'],'buy')
    if 'lat' not in d and 'lon' not in d and (not saved or saved['use_current']):raise ValueError('Get your current GPS location or choose a fixed buying address before checkout')
    p,lat,lon,km=origin(c,t,u,{k:[str(d[k])] for k in ('lat','lon','radius','unit') if k in d})
    if lat is None:raise ValueError('Set your buying address or GPS location before checkout')
    if not decorate(c,l,p,lat,lon,km):raise ValueError('This item is outside your buying radius, the seller’s sale radius, or the marketplace area')

def geocoder_key(c):
    row=c.execute("SELECT value FROM settings WHERE name='geocoder_key'").fetchone()
    if row is None:return os.environ.get('NEARMARKET_GEOAPIFY_KEY','')
    if not row[0]:return ''
    try:
        payload=json.loads(gateway_admin.cipher().decrypt(row[0].encode()).decode())
        if payload.get('type')!='geocoder':raise ValueError('Invalid geocoding credential context')
        return payload['value']
    except Exception:raise ValueError('Address lookup credentials are unavailable') from None

def lookup(address,key):
    from urllib.parse import urlencode
    url='https://api.geoapify.com/v1/geocode/search?'+urlencode({'text':address,'format':'json','limit':5,'apiKey':key})
    req=urllib.request.Request(url,headers={'User-Agent':'NearMarket address lookup'})
    try:
        with urllib.request.build_opener(gateway_admin.NoRedirect()).open(req,timeout=10) as r:data=json.load(r)
        results=[]
        for item in data.get('results',[])[:5]:
            lat,lon=point(item.get('lat'),item.get('lon'))
            results.append({'lat':lat,'lon':lon,'label':str(item.get('formatted',''))[:300],'area':', '.join(str(item[k]) for k in ('city','state','country') if item.get(k))[:100]})
        return results
    except (OSError,ValueError,TypeError):raise ValueError('Address lookup failed. Use GPS or enter coordinates instead.') from None

def save_profile(c,t,uid,d,admin=False):
    kind=d.get('kind')
    if kind not in ('buy','sell'):raise ValueError('Select buying or selling')
    p=policy(c,t['id']);old=profile(c,t['id'],uid,kind)
    if old and old['locked'] and not admin:raise ValueError('This location is managed by the super admin')
    lat,lon=point(d.get('lat'),d.get('lon'));km=radius(d.get('radius'),d.get('unit','km'),p['max_'+kind+'_km'])
    if not in_market(p,lat,lon):raise ValueError('Selected location is outside this marketplace’s allowed area')
    label=str(d.get('label','')).strip()
    if not 1<=len(label)<=300:raise ValueError('Enter an address or area label (up to 300 characters)')
    locked=int(bool(d.get('locked'))) if admin else 0
    c.execute('INSERT INTO trade_locations(tenant_id,user_id,kind,lat,lon,radius_km,label,unit,locked,use_current) VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(tenant_id,user_id,kind) DO UPDATE SET lat=excluded.lat,lon=excluded.lon,radius_km=excluded.radius_km,label=excluded.label,unit=excluded.unit,locked=excluded.locked,use_current=excluded.use_current',(t['id'],uid,kind,lat,lon,km,label,d.get('unit','km'),locked,int(bool(d.get('use_current',True)))))

def handle(h,c,u,route,method,d,q,t):
    if route not in ('/api/location-settings','/api/admin/locations','/api/geocode'):return False
    admin=bool(u and u['role']=='superadmin')
    if route=='/api/admin/locations' and not admin:h.send(403,{'error':'Super admin access required'});return True
    p=policy(c,t['id'])
    if method=='GET':
        if route=='/api/geocode':h.send(405,{'error':'Use a manual POST address search'});return True
        try:geocoding=bool(geocoder_key(c))
        except ValueError:geocoding=False
        if route=='/api/admin/locations':
            users=c.execute('SELECT id,name,email FROM users WHERE disabled=0'+('' if t['id']==1 else ' AND id IN (SELECT user_id FROM memberships WHERE tenant_id=?)'),() if t['id']==1 else (t['id'],)).fetchall()
            h.send(200,{'policy':p,'geocoding':geocoding,'users':[dict(r) for r in users],'profiles':[dict(r) for r in c.execute('SELECT * FROM trade_locations WHERE tenant_id=?',(t['id'],))],'listings':[dict(r) for r in c.execute('SELECT l.id,l.title,COALESCE(r.lat,l.lat) lat,COALESCE(r.lon,l.lon) lon,r.radius_km,r.label FROM listings l LEFT JOIN listing_locations r ON r.listing_id=l.id WHERE l.tenant_id=? ORDER BY l.id DESC LIMIT 500',(t['id'],))]});return True
        public=dict(p)
        for field in ('center_lat','center_lon'):
            if public[field] is not None:public[field]=round(public[field],2)
        h.send(200,{'policy':public,'geocoding':geocoding,'profiles':{k:dict(r) for k in ('buy','sell') if (r:=profile(c,t['id'],u['id'] if u else None,k))}});return True
    if not u:h.send(401,{'error':'Sign in first'});return True
    from tenants import member
    if not member(c,u,t):h.send(403,{'error':'Marketplace membership required'});return True
    if route=='/api/geocode':
        address=str(d.get('address','')).strip()
        if not 3<=len(address)<=300:raise ValueError('Enter an address or place (3–300 characters)')
        key=geocoder_key(c)
        if not key:raise ValueError('Address lookup is not configured. Use GPS or coordinates, or ask the super admin to configure Geoapify.')
        digest=hashlib.sha256(address.casefold().encode()).hexdigest()
        cached=c.execute('SELECT response FROM geocode_cache WHERE user_id=? AND tenant_id=? AND query_hash=? AND created>?',(u['id'],t['id'],digest,time.time()-604800)).fetchone()
        if cached:h.send(200,{'results':json.loads(cached[0]),'attribution':'Powered by Geoapify | OpenStreetMap contributors'});return True
        minute=int(time.time()//60);c.execute('BEGIN IMMEDIATE')
        row=c.execute('SELECT count FROM geocode_rate WHERE user_id=? AND window=?',(u['id'],minute)).fetchone()
        if row and row[0]>=10:h.send(429,{'error':'Too many address lookups; retry next minute'});return True
        c.execute('INSERT INTO geocode_rate VALUES(?,?,1) ON CONFLICT(user_id) DO UPDATE SET window=excluded.window,count=CASE WHEN window=excluded.window THEN count+1 ELSE 1 END',(u['id'],minute));c.commit()
        results=lookup(address,key)
        c.execute('INSERT OR REPLACE INTO geocode_cache VALUES(?,?,?,?,?)',(u['id'],t['id'],digest,json.dumps(results),time.time()))
        c.execute('DELETE FROM geocode_cache WHERE user_id=? AND created<?',(u['id'],time.time()-604800))
        h.send(200,{'results':results,'attribution':'Powered by Geoapify | OpenStreetMap contributors'});return True
    if route=='/api/location-settings':save_profile(c,t,u['id'],d)
    else:
        action=d.get('action','policy')
        if action=='policy':
            values={k:radius(d.get(k,p[k])) for k in ('default_buy_km','default_sell_km','max_buy_km','max_sell_km','market_radius_km')}
            if values['default_buy_km']>values['max_buy_km'] or values['default_sell_km']>values['max_sell_km']:raise ValueError('Default radius cannot exceed the maximum')
            center=point(d.get('center_lat'),d.get('center_lon')) if d.get('center_lat') not in ('',None) or d.get('center_lon') not in ('',None) else (None,None)
            restricted=bool(d.get('restrict_marketplace'))
            if restricted and center[0] is None:raise ValueError('Set a center before restricting the marketplace area')
            label=str(d.get('area_label','')).strip()
            if len(label)>100:raise ValueError('Area label is too long')
            c.execute('INSERT OR REPLACE INTO location_policies VALUES(?,?,?,?,?,?,?,?,?,?)',(t['id'],values['default_buy_km'],values['default_sell_km'],values['max_buy_km'],values['max_sell_km'],*center,label,values['market_radius_km'],int(restricted)))
        elif action=='user':
            uid=int(d.get('user_id',0))
            if not c.execute('SELECT 1 FROM users WHERE id=? AND disabled=0',(uid,)).fetchone() or (t['id']!=1 and not c.execute('SELECT 1 FROM memberships WHERE user_id=? AND tenant_id=?',(uid,t['id'])).fetchone()):raise ValueError('Choose an active marketplace member')
            save_profile(c,t,uid,d,True)
        elif action=='listing':
            lid=int(d.get('listing',0));l=c.execute('SELECT * FROM listings WHERE id=? AND tenant_id=?',(lid,t['id'])).fetchone()
            if not l:raise ValueError('Listing not found in this marketplace')
            if c.execute("SELECT 1 FROM orders WHERE listing=? AND status IN ('pending','paid')",(lid,)).fetchone():raise ValueError('A pending or paid order locks this listing')
            save_listing(c,t,l['seller'],lid,d)
        elif action=='geocoder':
            c.execute('BEGIN IMMEDIATE');status=gateway_admin.reauthenticate(c,u,d.get('current_password'))
            if status!=200:h.send(status,{'error':'Current password required, or password check rate-limited'});return True
            key=str(d.get('key','')).strip()
            if d.get('clear'):encrypted=''
            else:
                if not re.fullmatch(r'[A-Za-z0-9_-]{16,256}',key):raise ValueError('Enter a valid Geoapify API key')
                encrypted=gateway_admin.cipher().encrypt(json.dumps({'type':'geocoder','value':key}).encode()).decode()
            c.execute("INSERT INTO settings VALUES('geocoder_key',?) ON CONFLICT(name) DO UPDATE SET value=excluded.value",(encrypted,))
        else:raise ValueError('Unknown location action')
        c.execute('INSERT INTO audit(actor,action,target,created) VALUES(?,?,?,?)',(u['id'],'locations:'+action,str(t['id']),time.time()))
    h.send(200,{'ok':True});return True
