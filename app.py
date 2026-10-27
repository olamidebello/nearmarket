import tenants, payments
import os, sqlite3, json, secrets, hashlib, hmac, math, time, re, argparse
from pathlib import Path
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

ROOT=Path(__file__).parent
DATA=Path(os.environ.get('NEARMARKET_DATA',str(ROOT/'data')))
DATA.mkdir(parents=True,exist_ok=True)
def db():
    c=sqlite3.connect(DATA/'market.db'); c.row_factory=sqlite3.Row; c.execute('PRAGMA foreign_keys=ON'); return c

def init():
    with db() as c:
        c.executescript('''
        CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,name TEXT NOT NULL,email TEXT UNIQUE NOT NULL,password TEXT NOT NULL,salt TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY,user_id INTEGER REFERENCES users(id),expires REAL);
        CREATE TABLE IF NOT EXISTS listings(id INTEGER PRIMARY KEY,seller INTEGER REFERENCES users(id),title TEXT,description TEXT,price INTEGER,currency TEXT,category TEXT,condition TEXT,area TEXT,lat REAL,lon REAL,image TEXT,status TEXT DEFAULT 'available',created REAL);
        CREATE TABLE IF NOT EXISTS messages(id INTEGER PRIMARY KEY,listing INTEGER REFERENCES listings(id),sender INTEGER REFERENCES users(id),recipient INTEGER REFERENCES users(id),body TEXT,offer INTEGER,created REAL);
        CREATE TABLE IF NOT EXISTS favorites(user_id INTEGER REFERENCES users(id),listing INTEGER REFERENCES listings(id),PRIMARY KEY(user_id,listing));
        CREATE TABLE IF NOT EXISTS reports(id INTEGER PRIMARY KEY,user_id INTEGER REFERENCES users(id),listing INTEGER REFERENCES listings(id),reason TEXT,created REAL);
        CREATE TABLE IF NOT EXISTS api_keys(id INTEGER PRIMARY KEY,name TEXT,key_hash TEXT UNIQUE,prefix TEXT,scopes TEXT,expires REAL,revoked INTEGER DEFAULT 0,created REAL,last_used REAL);
        CREATE TABLE IF NOT EXISTS settings(name TEXT PRIMARY KEY,value TEXT);
        CREATE TABLE IF NOT EXISTS api_usage(key_id INTEGER,minute INTEGER,count INTEGER,PRIMARY KEY(key_id,minute));
        CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY,actor INTEGER,action TEXT,target TEXT,created REAL);
        ''')
        cols={r[1] for r in c.execute('PRAGMA table_info(users)')}
        if 'role' not in cols:c.execute("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'user'")
        if 'disabled' not in cols:c.execute('ALTER TABLE users ADD COLUMN disabled INTEGER DEFAULT 0')
        keycols={r[1] for r in c.execute('PRAGMA table_info(api_keys)')}
        for name,definition in {'rpm':'INTEGER DEFAULT 60','requests':'INTEGER DEFAULT 0','seller_id':'INTEGER REFERENCES users(id)'}.items():
            if name not in keycols:c.execute(f'ALTER TABLE api_keys ADD COLUMN {name} {definition}')
        c.execute("INSERT OR IGNORE INTO settings VALUES('api_enabled','1')")
        c.execute('DELETE FROM api_usage WHERE minute<?',(int(time.time()//60)-1440,))
        tenants.init(c);payments.init(c)


def distance(a,b,x,y):
    p,q=math.radians(a),math.radians(x)
    v=math.sin((q-p)/2)**2+math.cos(p)*math.cos(q)*math.sin(math.radians(y-b)/2)**2
    return 6371*2*math.asin(math.sqrt(min(1,max(0,v))))

def password(p,s): return hashlib.scrypt(p.encode(),salt=bytes.fromhex(s),n=16384,r=8,p=1).hex()
def require(ok,message):
    if not ok: raise ValueError(message)
def coordinate(v,limit):
    n=float(v); require(math.isfinite(n) and -limit<=n<=limit,'Invalid coordinates'); return n

def clean_listing(d):
    title=str(d.get('title','')).strip(); description=str(d.get('description','')).strip()
    require(3<=len(title)<=100,'Title must contain 3–100 characters')
    require(10<=len(description)<=5000,'Description must contain 10–5000 characters')
    amount=float(d.get('price',-1)); require(math.isfinite(amount) and 0<=amount<=10000000,'Invalid price')
    currency=d.get('currency','USD'); require(currency in ('USD','NGN','GBP','EUR','CAD'),'Unsupported currency')
    category=d.get('category'); require(category in ('Home','Electronics','Furniture','Fashion','Sports','Kids','Tools','Other'),'Select a category')
    condition=d.get('condition'); require(condition in ('New','Like new','Good','Fair'),'Select a condition')
    area=str(d.get('area','')).strip(); require(2<=len(area)<=100,'Enter your neighborhood or city')
    image=str(d.get('image','')); require(len(image)<=2800000 and (not image or re.fullmatch(r'data:image/(?:jpeg|png|webp);base64,[A-Za-z0-9+/=]+',image)),'Upload a JPEG, PNG, or WebP image under 2 MB')
    # Store only approximate coordinates to avoid exposing a home location.
    return (title,description,round(amount*100),currency,category,condition,area,round(coordinate(d.get('lat'),90),2),round(coordinate(d.get('lon'),180),2),image)

class Handler(BaseHTTPRequestHandler):
    def send(self,status,data,cookie=None):
        raw=json.dumps(data).encode(); self.send_response(status); self.send_header('Content-Type','application/json'); self.send_header('Cache-Control','no-store')
        self.send_header('X-Content-Type-Options','nosniff')
        if cookie:self.send_header('Set-Cookie',cookie)
        self.end_headers(); self.wfile.write(raw)
    def user(self,c):
        cookies=dict(p.strip().split('=',1) for p in self.headers.get('Cookie','').split(';') if '=' in p)
        return c.execute('SELECT u.id,u.name,u.role FROM users u JOIN sessions s ON u.id=s.user_id WHERE s.token=? AND s.expires>? AND u.disabled=0',(cookies.get('session',''),time.time())).fetchone()
    def do_GET(self):
        if self.path.startswith('/api/'):
            self.api('GET'); return
        path=urlparse(self.path).path
        files={'/':'index.html','/app.js':'app.js','/style.css':'style.css'}
        if path not in files:self.send(404,{'error':'Not found'});return
        raw=(ROOT/'static'/files[path]).read_bytes(); self.send_response(200)
        self.send_header('Content-Type',{'/':'text/html; charset=utf-8','/app.js':'text/javascript','/style.css':'text/css'}[path])
        self.send_header('X-Content-Type-Options','nosniff'); self.send_header('Referrer-Policy','same-origin')
        self.send_header('Content-Security-Policy',"default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; base-uri 'none'; frame-ancestors 'none'")
        self.end_headers();self.wfile.write(raw)
    def do_POST(self):
        if self.path.startswith('/api/webhooks/'):
            try:
                parts=urlparse(self.path).path.split('/')
                require(len(parts)==5 and parts[3] in ('stripe','paystack'),'Invalid webhook route')
                size=int(self.headers.get('Content-Length',0));require(0<size<=1000000,'Invalid payload size')
                raw=self.rfile.read(size)
                with db() as c:payments.webhook(self,c,parts[3],int(parts[4]),raw)
            except (ValueError,KeyError,TypeError):self.send(400,{'error':'Invalid webhook payload'})
            except Exception:self.send(500,{'error':'Webhook processing failed'})
            return
        self.api('POST')
    def api(self,method):
        try:
            p=urlparse(self.path); q=parse_qs(p.query); d={}
            if method=='POST':
                # Browser writes must originate on this host; JSON rejects cross-site form submissions.
                origin=self.headers.get('Origin')
                require(not origin or urlparse(origin).netloc==self.headers.get('Host'),'Invalid request origin')
                require(self.headers.get('Content-Type','').startswith('application/json'),'Expected JSON')
                size=int(self.headers.get('Content-Length',0));require(0<size<=3000000,'Request too large')
                d=json.loads(self.rfile.read(size)); require(isinstance(d,dict),'Invalid request')
            with db() as c:
                u=self.user(c); route=p.path
                t=tenants.selected(self,c)
                public_routes=('/api/tenants','/api/login','/api/signup','/api/me','/api/logout','/api/health','/api/admin')
                if not t['public'] and not tenants.member(c,u,t) and route not in public_routes and not route.startswith('/api/v1/'):
                    self.send(403,{'error':'Private marketplace membership required'});return
                if tenants.handle(self,c,u,route,method,d,t):return
                if payments.handle(self,c,u,route,method,d,t):return
                if route=='/api/admin':
                    if not u or u['role']!='superadmin':self.send(403,{'error':'Super admin access required'});return
                    if method=='GET':
                        self.send(200,{
                            'users':[dict(r) for r in c.execute('SELECT id,name,email,role,disabled FROM users')],
                            'listings':[dict(r) for r in c.execute('SELECT id,title,seller,status,area FROM listings ORDER BY id DESC LIMIT 500')],
                            'reports':[dict(r) for r in c.execute('SELECT * FROM reports ORDER BY id DESC LIMIT 500')],
                            'keys':[dict(r) for r in c.execute('SELECT id,name,prefix,scopes,expires,revoked,created,last_used,rpm,requests,seller_id,tenant_id FROM api_keys')],
                            'api_enabled':c.execute("SELECT value FROM settings WHERE name='api_enabled'").fetchone()[0]=='1',
                            'audit':[dict(r) for r in c.execute('SELECT * FROM audit ORDER BY id DESC LIMIT 100')]
                        });return
                    action=d.get('action'); target=str(d.get('id','')); extra={}
                    if action=='api_toggle':
                        require(isinstance(d.get('enabled'),bool),'Expected enabled boolean')
                        c.execute("UPDATE settings SET value=? WHERE name='api_enabled'",('1' if d['enabled'] else '0',))
                    elif action in ('create_key','edit_key'):
                        name=str(d.get('name','')).strip();require(2<=len(name)<=100,'Enter key name')
                        scopes=d.get('scopes',[]);require(isinstance(scopes,list) and len(scopes)>0 and all(x in ('listings:read','listings:write') for x in scopes),'Select valid scopes')
                        days=int(d.get('days',30));require(1<=days<=365,'Expiry must be 1–365 days')
                        key_tenant=int(d.get('tenant_id',t['id']))
                        require(c.execute('SELECT 1 FROM tenants WHERE id=? AND active=1',(key_tenant,)).fetchone(),'Choose an active marketplace')
                        rpm=int(d.get('rpm',60));require(1<=rpm<=10000,'Rate limit must be 1–10000 requests per minute')
                        seller_id=int(d['seller_id']) if d.get('seller_id') not in ('',None) else None
                        if seller_id is not None:require(c.execute('SELECT 1 FROM users WHERE id=? AND disabled=0',(seller_id,)).fetchone(),'Select an active seller')
                        if seller_id is not None:
                            require(key_tenant==1 or c.execute('SELECT 1 FROM memberships WHERE tenant_id=? AND user_id=?',(key_tenant,seller_id)).fetchone(),'Seller must belong to the selected marketplace')
                        if action=='create_key':
                            secret='nm_'+secrets.token_urlsafe(32)
                            cur=c.execute('INSERT INTO api_keys(name,key_hash,prefix,scopes,expires,created,rpm,seller_id,tenant_id) VALUES(?,?,?,?,?,?,?,?,?)',(name,hashlib.sha256(secret.encode()).hexdigest(),secret[:10],json.dumps(sorted(set(scopes))),time.time()+days*86400,time.time(),rpm,seller_id,key_tenant))
                            target=str(cur.lastrowid);extra={'secret':secret}
                        else:
                            require(c.execute('SELECT 1 FROM api_keys WHERE id=? AND revoked=0',(int(target),)).fetchone(),'Active key not found')
                            c.execute('UPDATE api_keys SET name=?,scopes=?,expires=?,rpm=?,seller_id=?,tenant_id=? WHERE id=?',(name,json.dumps(sorted(set(scopes))),time.time()+days*86400,rpm,seller_id,key_tenant,int(target)))
                    elif action=='rotate_key':
                        require(c.execute('SELECT 1 FROM api_keys WHERE id=? AND revoked=0 AND expires>?',(int(target),time.time())).fetchone(),'Active unexpired key not found')
                        secret='nm_'+secrets.token_urlsafe(32)
                        c.execute('UPDATE api_keys SET key_hash=?,prefix=? WHERE id=?',(hashlib.sha256(secret.encode()).hexdigest(),secret[:10],int(target)))
                        extra={'secret':secret}

                    elif action=='revoke_key':c.execute('UPDATE api_keys SET revoked=1 WHERE id=?',(int(target),))
                    elif action=='user':
                        uid=int(target);require(uid!=u['id'],'You cannot change your own admin access here')
                        role=d.get('role','user');require(role in ('user','superadmin'),'Invalid role')
                        disabled=int(bool(d.get('disabled')))
                        c.execute('UPDATE users SET role=?,disabled=? WHERE id=?',(role,disabled,uid))
                        c.execute('DELETE FROM sessions WHERE user_id=?',(uid,))
                    elif action=='listing':
                        require(not c.execute("SELECT 1 FROM orders WHERE listing=? AND status IN ('pending','paid')",(int(target),)).fetchone(),'A paid or pending order locks this listing')
                        status=d.get('status');require(status in ('available','reserved','sold','hidden'),'Invalid status')
                        c.execute('UPDATE listings SET status=? WHERE id=?',(status,int(target)))
                    elif action=='resolve_report':c.execute('DELETE FROM reports WHERE id=?',(int(target),))
                    else:raise ValueError('Unknown admin action')
                    c.execute('INSERT INTO audit(actor,action,target,created) VALUES(?,?,?,?)',(u['id'],action,target,time.time()))
                    self.send(200,{'ok':True,**extra});return
                if route.startswith('/api/v1/'):
                    if c.execute("SELECT value FROM settings WHERE name='api_enabled'").fetchone()[0]!='1':self.send(503,{'error':'Integration API is disabled by an administrator'});return
                    c.execute('BEGIN IMMEDIATE')
                    secret=self.headers.get('Authorization','').removeprefix('Bearer ')
                    key=c.execute('SELECT * FROM api_keys WHERE key_hash=? AND revoked=0 AND expires>?',(hashlib.sha256(secret.encode()).hexdigest(),time.time())).fetchone()
                    if not key:self.send(401,{'error':'Invalid or expired API key'});return
                    if key['tenant_id']!=t['id']:self.send(403,{'error':'Key belongs to another marketplace'});return
                    scope='listings:read' if method=='GET' else 'listings:write'
                    if scope not in json.loads(key['scopes']):self.send(403,{'error':'Key lacks required scope'});return
                    if key['seller_id'] is not None and not c.execute('SELECT 1 FROM users WHERE id=? AND disabled=0',(key['seller_id'],)).fetchone():self.send(403,{'error':'Linked seller is suspended'});return
                    minute=int(time.time()//60)
                    usage=c.execute('SELECT count FROM api_usage WHERE key_id=? AND minute=?',(key['id'],minute)).fetchone()
                    if usage and usage[0]>=key['rpm']:self.send(429,{'error':'Key rate limit exceeded; retry next minute'});return
                    c.execute('INSERT INTO api_usage VALUES(?,?,1) ON CONFLICT(key_id,minute) DO UPDATE SET count=count+1',(key['id'],minute))
                    c.execute('UPDATE api_keys SET last_used=?,requests=requests+1 WHERE id=?',(time.time(),key['id']))
                    c.execute('DELETE FROM api_usage WHERE key_id=? AND minute<?',(key['id'],minute-1440))
                    if route!='/api/v1/listings':self.send(404,{'error':'Not found'});return
                    if method=='GET':
                        self.send(200,[dict(r) for r in c.execute("SELECT id,title,description,price,currency,category,condition,area,lat,lon,status FROM listings WHERE status='available' AND tenant_id=? ORDER BY id DESC LIMIT 100",(t['id'],))]);return
                    # Integrations can only post for a real active account selected explicitly.
                    seller=int(d.get('seller',key['seller_id'] or 0))
                    if key['seller_id'] is not None and seller!=key['seller_id']:self.send(403,{'error':'Key is restricted to its linked seller'});return
                    require(c.execute('SELECT 1 FROM users WHERE id=? AND disabled=0',(seller,)).fetchone(),'Select an active seller ID')
                    require(t['id']==1 or c.execute('SELECT 1 FROM memberships WHERE tenant_id=? AND user_id=?',(t['id'],seller)).fetchone(),'Seller is not a marketplace member')
                    tenants.capacity(c,t)
                    values=clean_listing(d);cur=c.execute('INSERT INTO listings(seller,title,description,price,currency,category,condition,area,lat,lon,image,created) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',(seller,*values,time.time()))
                    c.execute('UPDATE listings SET tenant_id=? WHERE id=?',(t['id'],cur.lastrowid))
                    c.execute('INSERT INTO audit(actor,action,target,created) VALUES(NULL,?,?,?)',('api_key:'+str(key['id'])+':create_listing',str(cur.lastrowid),time.time()))
                    self.send(201,{'id':cur.lastrowid});return
                if route=='/api/health': self.send(200,{'status':'ok'});return
                if route=='/api/me':self.send(200,dict(u) if u else None);return
                if route in ('/api/signup','/api/login') and method=='POST':
                    email=str(d.get('email','')).strip().lower();pw=str(d.get('password',''))
                    require(re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+',email) and len(email)<=254,'Enter a valid email')
                    require(10<=len(pw)<=128,'Password must contain 10–128 characters')
                    if route.endswith('signup'):
                        name=str(d.get('name','')).strip();require(2<=len(name)<=60,'Enter your name')
                        salt=secrets.token_hex(16)
                        try:c.execute('INSERT INTO users(name,email,password,salt) VALUES(?,?,?,?)',(name,email,password(pw,salt),salt))
                        except sqlite3.IntegrityError:raise ValueError('Unable to create account with this email')
                    row=c.execute('SELECT * FROM users WHERE email=?',(email,)).fetchone()
                    require(row is not None and not row['disabled'] and hmac.compare_digest(row['password'],password(pw,row['salt'])),'Invalid email or password')
                    token=secrets.token_urlsafe(32);c.execute('DELETE FROM sessions WHERE expires<?',(time.time(),));c.execute('INSERT INTO sessions VALUES(?,?,?)',(token,row['id'],time.time()+604800))
                    secure='; Secure' if os.environ.get('COOKIE_SECURE')=='1' else ''
                    self.send(200,{'id':row['id'],'name':row['name'],'role':row['role']},f'session={token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=604800{secure}');return
                if route=='/api/listings' and method=='GET':
                    rows=c.execute('SELECT l.*,u.name seller_name FROM listings l JOIN users u ON l.seller=u.id WHERE l.tenant_id=? ORDER BY created DESC LIMIT 1000',(t['id'],)).fetchall();result=[]
                    lat=coordinate(q['lat'][0],90) if 'lat' in q else None;lon=coordinate(q['lon'][0],180) if lat is not None else None
                    radius=float(q.get('radius',['25'])[0]);require(math.isfinite(radius) and 0<radius<=10000,'Invalid radius')
                    for r in rows:
                        r=dict(r)
                        if q.get('mine') and (not u or r['seller']!=u['id']):continue
                        if not q.get('mine') and r['status']!='available':continue
                        if q.get('q') and q['q'][0].lower() not in (r['title']+' '+r['description']).lower():continue
                        if q.get('category') and r['category']!=q['category'][0]:continue
                        r['distance']=round(distance(lat,lon,r['lat'],r['lon']),1) if lat is not None else None
                        if r['distance'] is not None and r['distance']>radius:continue
                        r['saved']=bool(u and c.execute('SELECT 1 FROM favorites WHERE user_id=? AND listing=?',(u['id'],r['id'])).fetchone())
                        if q.get('saved') and not r['saved']:continue
                        result.append(r)
                    if lat is not None:result.sort(key=lambda r:r['distance'])
                    self.send(200,result);return
                if not u:self.send(401,{'error':'Please sign in first'});return
                if route=='/api/logout' and method=='POST':
                    c.execute('DELETE FROM sessions WHERE user_id=?',(u['id'],));self.send(200,{'ok':True},'session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0');return
                if route=='/api/listings' and method=='POST':
                    require(tenants.member(c,u,t),'Join this marketplace before selling')
                    c.execute('BEGIN IMMEDIATE')
                    tenants.capacity(c,t)
                    values=clean_listing(d);cur=c.execute('INSERT INTO listings(seller,title,description,price,currency,category,condition,area,lat,lon,image,created) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',(u['id'],*values,time.time()))
                    c.execute('UPDATE listings SET tenant_id=?,online=? WHERE id=?',(t['id'],int(bool(d.get('online'))),cur.lastrowid))
                    self.send(201,{'id':cur.lastrowid});return
                if route=='/api/messages' and method=='GET':
                    rows=c.execute('SELECT m.*,l.title,u.name sender_name FROM messages m JOIN listings l ON l.id=m.listing JOIN users u ON u.id=m.sender WHERE l.tenant_id=? AND (sender=? OR recipient=?) ORDER BY created DESC LIMIT 500',(t['id'],u['id'],u['id'])).fetchall();self.send(200,[dict(r) for r in rows]);return
                if route in ('/api/status','/api/favorite','/api/messages','/api/report','/api/edit') and method=='POST':
                    listing=c.execute('SELECT * FROM listings WHERE id=? AND tenant_id=?',(int(d.get('listing',0)),t['id'])).fetchone();require(listing is not None,'Listing not found');lid=listing['id']
                    require(tenants.member(c,u,t),'Marketplace membership required')
                    if route in ('/api/status','/api/edit'):
                        require(not c.execute("SELECT 1 FROM orders WHERE listing=? AND status IN ('pending','paid')",(lid,)).fetchone(),'A paid or pending order locks this listing')
                        require(listing['status']!='hidden','A moderator has hidden this listing')
                        require(listing['seller']==u['id'],'Only the seller can change this listing')
                        if route=='/api/edit':
                            values=clean_listing(d);c.execute('UPDATE listings SET online=? WHERE id=?',(int(bool(d.get('online'))),lid));c.execute('UPDATE listings SET title=?,description=?,price=?,currency=?,category=?,condition=?,area=?,lat=?,lon=?,image=? WHERE id=?',(*values,lid))
                        else:
                            require(d.get('status') in ('available','reserved','sold'),'Invalid status')
                            if d['status'] in ('available','reserved') and listing['status']=='sold':tenants.capacity(c,t)
                            c.execute('UPDATE listings SET status=? WHERE id=?',(d['status'],lid))
                    elif route=='/api/favorite':
                        exists=c.execute('DELETE FROM favorites WHERE user_id=? AND listing=?',(u['id'],lid)).rowcount
                        if not exists:c.execute('INSERT INTO favorites VALUES(?,?)',(u['id'],lid))
                    elif route=='/api/report':
                        reason=str(d.get('reason','')).strip();require(5<=len(reason)<=1000,'Describe the issue (5–1000 characters)');c.execute('INSERT INTO reports(user_id,listing,reason,created) VALUES(?,?,?,?)',(u['id'],lid,reason,time.time()))
                    else:
                        recipient=listing['seller']
                        if u['id']==recipient:
                            recipient=int(d.get('recipient',0));require(c.execute('SELECT 1 FROM messages WHERE listing=? AND sender=? AND recipient=?',(lid,recipient,u['id'])).fetchone(),'Select an existing buyer conversation')
                        body=str(d.get('body','')).strip();require(1<=len(body)<=2000,'Message must contain 1–2000 characters')
                        offer=None
                        if d.get('offer') not in (None,''):
                            amount=float(d['offer']);require(math.isfinite(amount) and 0<amount<=10000000,'Invalid offer');offer=round(amount*100)
                        c.execute('INSERT INTO messages(listing,sender,recipient,body,offer,created) VALUES(?,?,?,?,?,?)',(lid,u['id'],recipient,body,offer,time.time()))
                    self.send(200,{'ok':True});return
                self.send(404,{'error':'Not found'})
        except (ValueError,TypeError,KeyError,OverflowError,json.JSONDecodeError) as e:self.send(400,{'error':str(e) or 'Invalid request'})
        except Exception:
            self.log_error('Request failed');self.send(500,{'error':'Request failed. Please try again.'})

if __name__=='__main__':
    init()
    parser=argparse.ArgumentParser();parser.add_argument('--promote-admin',metavar='EMAIL');args=parser.parse_args()
    if args.promote_admin:
        with db() as c:
            changed=c.execute("UPDATE users SET role='superadmin',disabled=0 WHERE email=?",(args.promote_admin.lower(),)).rowcount
        if not changed:raise SystemExit('Create the account first, then promote it.')
        print('Super admin enabled.');raise SystemExit(0)
    ThreadingHTTPServer((os.environ.get('HOST','127.0.0.1'),int(os.environ.get('PORT','8080'))),Handler).serve_forever()
