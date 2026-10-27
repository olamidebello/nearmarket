"""Tenant lifecycle, membership and marketplace administration."""
import re,time,json

def init(c):
    c.executescript('''
    CREATE TABLE IF NOT EXISTS tenants(id INTEGER PRIMARY KEY,name TEXT NOT NULL,slug TEXT UNIQUE NOT NULL,active INTEGER DEFAULT 1,public INTEGER DEFAULT 1,listing_limit INTEGER DEFAULT 1000,payments INTEGER DEFAULT 0,stripe INTEGER DEFAULT 0,paystack INTEGER DEFAULT 0,created REAL);
    CREATE TABLE IF NOT EXISTS memberships(tenant_id INTEGER REFERENCES tenants(id),user_id INTEGER REFERENCES users(id),role TEXT DEFAULT 'member',PRIMARY KEY(tenant_id,user_id));
    INSERT OR IGNORE INTO tenants(id,name,slug,created) VALUES(1,'NearMarket Community','community',0);
    ''')
    for table in ('listings','api_keys'):
        cols={r[1] for r in c.execute('PRAGMA table_info('+table+')')}
        if 'tenant_id' not in cols:c.execute('ALTER TABLE '+table+' ADD COLUMN tenant_id INTEGER NOT NULL DEFAULT 1 REFERENCES tenants(id)')
    cols={r[1] for r in c.execute('PRAGMA table_info(listings)')}
    if 'online' not in cols:c.execute('ALTER TABLE listings ADD COLUMN online INTEGER DEFAULT 0')
    c.execute('CREATE INDEX IF NOT EXISTS listings_tenant ON listings(tenant_id,status)')

def selected(h,c):
    tid=int(h.headers.get('X-Tenant-ID','1'))
    t=c.execute('SELECT * FROM tenants WHERE id=?',(tid,)).fetchone()
    if not t or not t['active']:raise ValueError('Marketplace is unavailable')
    return t

def member(c,u,t):
    if not u:return False
    if u['role']=='superadmin':return True
    if t['id']==1:
        return True
    return bool(c.execute('SELECT 1 FROM memberships WHERE tenant_id=? AND user_id=?',(t['id'],u['id'])).fetchone())

def manager(c,u,t):
    return bool(u and (u['role']=='superadmin' or c.execute("SELECT 1 FROM memberships WHERE tenant_id=? AND user_id=? AND role='admin'",(t['id'],u['id'])).fetchone()))

def capacity(c,t):
    if c.execute("SELECT count(*) FROM listings WHERE tenant_id=? AND status IN ('available','reserved')",(t['id'],)).fetchone()[0]>=t['listing_limit']:raise ValueError('Marketplace listing quota reached')

def handle(h,c,u,route,method,d,t):
    if route=='/api/tenants' and method=='GET':
        rows=c.execute('SELECT * FROM tenants WHERE active=1 ORDER BY name').fetchall()
        h.send(200,[{**dict(r),'member':member(c,u,r),'manager':manager(c,u,r)} for r in rows if r['public'] or member(c,u,r)])
        return True
    if route=='/api/tenant/join' and method=='POST':
        if not u:h.send(401,{'error':'Sign in to join'});return True
        if not t['public']:h.send(403,{'error':'Ask the marketplace administrator for membership'});return True
        c.execute("INSERT OR IGNORE INTO memberships VALUES(?,?,'member')",(t['id'],u['id']))
        h.send(200,{'ok':True});return True
    if route not in ('/api/tenant/admin','/api/tenant/provision'):return False
    global_admin=bool(u and u['role']=='superadmin')
    if not manager(c,u,t):h.send(403,{'error':'Marketplace administrator access required'});return True
    if method=='GET':
        from payments import gateway_status
        ts=[dict(r) for r in c.execute('SELECT * FROM tenants ORDER BY id')] if global_admin else [dict(t)]
        h.send(200,{'tenants':ts,'current':dict(t),'gateways':gateway_status(t),
            'members':[dict(r) for r in c.execute('SELECT m.user_id,m.role,u.name,u.email FROM memberships m JOIN users u ON u.id=m.user_id WHERE tenant_id=?',(t['id'],))],
            'listings':[dict(r) for r in c.execute('SELECT id,title,status,seller FROM listings WHERE tenant_id=? ORDER BY id DESC LIMIT 500',(t['id'],))],
            'reports':[dict(r) for r in c.execute('SELECT r.* FROM reports r JOIN listings l ON l.id=r.listing WHERE l.tenant_id=?',(t['id'],))]});return True
    action=d.get('action');target=str(t['id'])
    if action=='create':
        if not global_admin:h.send(403,{'error':'Only super admins can create marketplaces'});return True
        name=str(d.get('name','')).strip();slug=str(d.get('slug','')).strip().lower()
        if not 2<=len(name)<=80 or not re.fullmatch('[a-z0-9][a-z0-9-]{1,49}',slug):raise ValueError('Enter a name and a unique lowercase slug (2–50 letters, digits or hyphens)')
        owner=c.execute('SELECT id FROM users WHERE email=? AND disabled=0',(str(d.get('owner','')).strip().lower(),)).fetchone()
        if not owner:raise ValueError('Owner must have an active registered account')
        cur=c.execute('INSERT INTO tenants(name,slug,public,created) VALUES(?,?,?,?)',(name,slug,int(bool(d.get('public',True))),time.time()));target=str(cur.lastrowid)
        c.execute("INSERT INTO memberships VALUES(?,?,'admin')",(cur.lastrowid,owner['id']))
    elif action=='settings':
        name=str(d.get('name','')).strip()
        if not 2<=len(name)<=80:raise ValueError('Name must contain 2–80 characters')
        c.execute('UPDATE tenants SET name=?,public=? WHERE id=?',(name,int(bool(d.get('public'))),t['id']))
        if global_admin:
            limit=int(d.get('listing_limit',1000))
            if not 1<=limit<=100000:raise ValueError('Listing limit must be 1–100000')
            c.execute('UPDATE tenants SET listing_limit=?,payments=?,stripe=?,paystack=? WHERE id=?',(limit,int(bool(d.get('payments'))),int(bool(d.get('stripe'))),int(bool(d.get('paystack'))),t['id']))
    elif action=='suspend':
        if not global_admin:h.send(403,{'error':'Only super admins can suspend marketplaces'});return True
        tid=int(d['id'])
        if tid==1:raise ValueError('The default community cannot be suspended')
        c.execute('UPDATE tenants SET active=? WHERE id=?',(int(bool(d.get('active'))),tid));target=str(tid)
    elif action=='member':
        row=c.execute('SELECT id FROM users WHERE email=? AND disabled=0',(str(d.get('email','')).strip().lower(),)).fetchone()
        if not row:raise ValueError('Active user not found')
        role=d.get('role')
        if role not in ('member','admin','remove'):raise ValueError('Invalid membership role')
        if row['id']==u['id']:raise ValueError('You cannot remove or change your own membership here')
        if role=='remove':c.execute('DELETE FROM memberships WHERE tenant_id=? AND user_id=?',(t['id'],row['id']))
        else:c.execute('INSERT INTO memberships VALUES(?,?,?) ON CONFLICT(tenant_id,user_id) DO UPDATE SET role=excluded.role',(t['id'],row['id'],role))
        target=f"{t['id']}:user:{row['id']}"
    elif action=='listing':
        status=d.get('status')
        if status not in ('available','hidden','sold'):raise ValueError('Invalid status')
        row=c.execute('SELECT id FROM listings WHERE id=? AND tenant_id=?',(int(d['id']),t['id'])).fetchone()
        if not row:raise ValueError('Listing not found in this marketplace')
        if c.execute("SELECT 1 FROM orders WHERE listing=? AND status IN ('pending','paid')",(row['id'],)).fetchone():raise ValueError('A payment is pending for this item')
        c.execute('UPDATE listings SET status=? WHERE id=?',(status,row['id']));target=str(row['id'])
    elif action=='resolve_report':
        c.execute('DELETE FROM reports WHERE id=? AND listing IN (SELECT id FROM listings WHERE tenant_id=?)',(int(d['id']),t['id']))
    else:raise ValueError('Unknown marketplace action')
    c.execute('INSERT INTO audit(actor,action,target,created) VALUES(?,?,?,?)',(u['id'],'tenant:'+str(action),target,time.time()))
    h.send(200,{'ok':True});return True
