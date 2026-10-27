"""Hosted gateway adapters. Payment status only changes on signed provider events."""
import gateway_admin
import os,json,time,secrets,hmac,hashlib,urllib.request,urllib.parse

def init(c):
    c.executescript('''
    CREATE TABLE IF NOT EXISTS orders(id TEXT PRIMARY KEY,tenant_id INTEGER REFERENCES tenants(id),listing INTEGER REFERENCES listings(id),buyer INTEGER REFERENCES users(id),seller INTEGER REFERENCES users(id),amount INTEGER,currency TEXT,gateway TEXT,status TEXT DEFAULT 'pending',provider_ref TEXT,checkout_url TEXT,created REAL,paid REAL);
    CREATE UNIQUE INDEX IF NOT EXISTS order_item_active ON orders(listing) WHERE status IN ('pending','paid');
    CREATE TABLE IF NOT EXISTS payment_events(tenant_id INTEGER,gateway TEXT,event_id TEXT,created REAL,PRIMARY KEY(tenant_id,gateway,event_id));
    ''')
    gateway_admin.init(c)
    cols={r[1] for r in c.execute('PRAGMA table_info(orders)')}
    for name,definition in {'pickup_code':'TEXT','collected':'REAL','mode':'TEXT'}.items():
        if name not in cols:c.execute(f'ALTER TABLE orders ADD COLUMN {name} {definition}')
    c.execute("CREATE TABLE IF NOT EXISTS disputes(id INTEGER PRIMARY KEY,order_id TEXT UNIQUE REFERENCES orders(id),buyer INTEGER,reason TEXT,status TEXT DEFAULT 'open',resolution TEXT,created REAL)")

def credential(t,g,suffix='SECRET',mode=None):
    return gateway_admin.read_secret(t['id'],g,suffix,mode)

def gateway_status(t):
    return gateway_admin.status(t)

def provider_post(url,payload,secret,form=False,idempotency=None):
    body=urllib.parse.urlencode(payload).encode() if form else json.dumps(payload).encode()
    headers={'Authorization':'Bearer '+secret,'Content-Type':'application/x-www-form-urlencoded' if form else 'application/json'}
    if idempotency:headers['Idempotency-Key']=idempotency
    req=urllib.request.Request(url,data=body,headers=headers)
    with urllib.request.urlopen(req,timeout=20) as r:return json.load(r)

def checkout(t,g,o,email,title):
    base=os.environ.get('NEARMARKET_PUBLIC_URL','').rstrip('/')
    p=urllib.parse.urlparse(base)
    if p.scheme!='https' or not p.netloc or p.query or p.fragment:raise ValueError('Configure NEARMARKET_PUBLIC_URL as the public HTTPS origin')
    if not gateway_status(t)[g]['ready']:raise ValueError('Gateway is not configured or enabled')
    mode=o['mode'] if 'mode' in o.keys() and o['mode'] else gateway_status(t)[g]['mode']
    if g=='stripe':
        r=provider_post('https://api.stripe.com/v1/checkout/sessions',{'mode':'payment','customer_email':email,'client_reference_id':o['id'],'metadata[order_id]':o['id'],'line_items[0][price_data][currency]':o['currency'].lower(),'line_items[0][price_data][unit_amount]':o['amount'],'line_items[0][price_data][product_data][name]':title,'line_items[0][quantity]':1,'success_url':base+'/?order='+o['id'],'cancel_url':base+'/?order='+o['id'],'expires_at':int(time.time())+1800},credential(t,g,mode=mode),True,o['id'])
        ref,url=r['id'],r['url']
    else:
        if o['currency']!='NGN':raise ValueError('Paystack checkout currently supports NGN listings only')
        r=provider_post('https://api.paystack.co/transaction/initialize',{'email':email,'amount':o['amount'],'currency':o['currency'],'reference':o['id'],'callback_url':base+'/?order='+o['id'],'metadata':{'order_id':o['id']}},credential(t,g,mode=mode))
        if not r.get('status'):raise ValueError('Gateway declined checkout initialization')
        ref,url=r['data']['reference'],r['data']['authorization_url']
    host=urllib.parse.urlparse(url)
    if host.scheme!='https' or host.hostname not in ('checkout.stripe.com','checkout.paystack.com'):raise ValueError('Unexpected gateway checkout URL')
    return ref,url

def handle(h,c,u,route,method,d,t):
    if route=='/api/gateways' and method=='GET':
        h.send(200,{g:{k:v for k,v in s.items() if k in ('ready','mode')} for g,s in gateway_status(t).items()});return True
    if route=='/api/orders' and method=='GET':
        if not u:h.send(401,{'error':'Sign in first'});return True
        from tenants import manager
        if manager(c,u,t):rows=c.execute('SELECT * FROM orders WHERE tenant_id=? ORDER BY created DESC LIMIT 500',(t['id'],))
        else:rows=c.execute('SELECT * FROM orders WHERE tenant_id=? AND (buyer=? OR seller=?) ORDER BY created DESC LIMIT 500',(t['id'],u['id'],u['id']))
        result=[]
        for row in rows:
            r=dict(row)
            if r['buyer']!=u['id']:r.pop('pickup_code',None)
            dispute=c.execute('SELECT id,reason,status,resolution FROM disputes WHERE order_id=?',(r['id'],)).fetchone()
            r['dispute']=dict(dispute) if dispute else None
            result.append(r)
        h.send(200,result);return True
    if route in ('/api/orders/pickup','/api/orders/dispute','/api/orders/resolve') and method=='POST':
        if not u:h.send(401,{'error':'Sign in first'});return True
        from tenants import manager
        o=c.execute('SELECT * FROM orders WHERE id=? AND tenant_id=?',(str(d.get('order','')),t['id'])).fetchone()
        if not o:raise ValueError('Order not found')
        if route.endswith('/pickup'):
            if u['id']!=o['seller']:h.send(403,{'error':'Only the seller can confirm pickup'});return True
            if o['status']!='paid' or o['collected']:raise ValueError('Order is not awaiting pickup')
            code=str(d.get('code','')).upper()
            if not o['pickup_code'] or not hmac.compare_digest(o['pickup_code'],code):raise ValueError('Pickup code does not match')
            c.execute('UPDATE orders SET collected=? WHERE id=?',(time.time(),o['id']))
        elif route.endswith('/dispute'):
            if u['id']!=o['buyer']:h.send(403,{'error':'Only the buyer can open an issue'});return True
            reason=str(d.get('reason','')).strip()
            if not 10<=len(reason)<=2000:raise ValueError('Describe the issue in 10–2000 characters')
            if c.execute('SELECT 1 FROM disputes WHERE order_id=?',(o['id'],)).fetchone():raise ValueError('An issue already exists for this order')
            c.execute('INSERT INTO disputes(order_id,buyer,reason,created) VALUES(?,?,?,?)',(o['id'],u['id'],reason,time.time()))
        else:
            if not manager(c,u,t):h.send(403,{'error':'Marketplace administrator required'});return True
            resolution=str(d.get('resolution','')).strip()
            if not 5<=len(resolution)<=2000:raise ValueError('Enter a resolution in 5–2000 characters')
            c.execute("UPDATE disputes SET status='resolved',resolution=? WHERE order_id=?",(resolution,o['id']))
        c.execute('INSERT INTO audit(actor,action,target,created) VALUES(?,?,?,?)',(u['id'],route,o['id'],time.time()))
        h.send(200,{'ok':True});return True
    if route!='/api/checkout' or method!='POST':return False
    if not u:h.send(401,{'error':'Sign in first'});return True
    from tenants import member
    if not member(c,u,t):h.send(403,{'error':'Join this marketplace first'});return True
    g=d.get('gateway')
    if g not in ('stripe','paystack'):raise ValueError('Choose Stripe or Paystack')
    if not gateway_status(t)[g]['ready']:raise ValueError('Gateway is not configured or enabled')
    base=urllib.parse.urlparse(os.environ.get('NEARMARKET_PUBLIC_URL',''))
    if base.scheme!='https' or not base.netloc:raise ValueError('Configure the public HTTPS URL before checkout')
    c.execute('BEGIN IMMEDIATE')
    l=c.execute('SELECT * FROM listings WHERE id=? AND tenant_id=?',(int(d.get('listing',0)),t['id'])).fetchone()
    if not l or l['status']!='available' or not l['online']:raise ValueError('Item is not available for online checkout')
    if l['seller']==u['id']:raise ValueError('You cannot buy your own item')
    if l['price']<=0:raise ValueError('Arrange free-item pickup directly with the seller')
    if g=='paystack' and l['currency']!='NGN':raise ValueError('Paystack currently supports NGN listings only')
    oid='nmorder_'+secrets.token_hex(16)
    c.execute('INSERT INTO orders(id,tenant_id,listing,buyer,seller,amount,currency,gateway,created,mode) VALUES(?,?,?,?,?,?,?,?,?,?)',(oid,t['id'],l['id'],u['id'],l['seller'],l['price'],l['currency'],g,time.time(),gateway_status(t)[g]['mode']))
    c.execute("UPDATE listings SET status='reserved' WHERE id=?",(l['id'],));c.commit()
    # Persist reservation before network I/O; uncertain failures remain pending for reconciliation.
    o=c.execute('SELECT * FROM orders WHERE id=?',(oid,)).fetchone()
    email=c.execute('SELECT email FROM users WHERE id=?',(u['id'],)).fetchone()[0]
    try:ref,url=checkout(t,g,o,email,l['title'])
    except Exception:
        h.send(502,{'error':'Checkout could not be confirmed. Item is reserved; contact the marketplace administrator.','order':oid});return True
    c.execute('UPDATE orders SET provider_ref=?,checkout_url=? WHERE id=?',(ref,url,oid))
    h.send(201,{'id':oid,'url':url});return True

def signature(g,raw,headers,t,mode=None):
    if mode is None:
        return any(signature(g,raw,headers,t,m) for m in ('test','live'))
    if g=='paystack':
        try:secret=credential(t,g,mode=mode)
        except ValueError:return False
        return bool(secret and hmac.compare_digest(hmac.new(secret.encode(),raw,hashlib.sha512).hexdigest(),headers.get('x-paystack-signature','')))
    try:secret=credential(t,g,'WEBHOOK_SECRET',mode)
    except ValueError:return False
    if not secret:return False
    values={}
    for part in headers.get('Stripe-Signature','').split(','):
        if '=' in part:
            k,v=part.split('=',1);values.setdefault(k,[]).append(v)
    stamp=values.get('t',[''])[0]
    try:
        if abs(time.time()-int(stamp))>300:return False
    except ValueError:return False
    sig=hmac.new(secret.encode(),stamp.encode()+b'.'+raw,hashlib.sha256).hexdigest()
    return any(hmac.compare_digest(sig,v) for v in values.get('v1',[]))

def webhook(h,c,g,tid,raw):
    t=c.execute('SELECT * FROM tenants WHERE id=?',(tid,)).fetchone()
    verified_mode=next((m for m in ('test','live') if t and signature(g,raw,h.headers,t,m)),None)
    if not verified_mode:h.send(400,{'error':'Invalid signature'});return
    event=json.loads(raw);obj=event.get('data',{}).get('object',{}) if g=='stripe' else event.get('data',{})
    kind=event.get('type') if g=='stripe' else event.get('event')
    if g=='stripe':
        oid=obj.get('metadata',{}).get('order_id');eid=str(event.get('id',''))
        paid=kind in ('checkout.session.completed','checkout.session.async_payment_succeeded') and obj.get('payment_status')=='paid'
        expired=kind=='checkout.session.expired'
        amount=obj.get('amount_total');currency=str(obj.get('currency','')).upper();ref=obj.get('id')
    else:
        oid=obj.get('reference');eid=str(obj.get('id',''))+':'+str(kind)
        paid=kind=='charge.success' and obj.get('status')=='success';expired=False
        amount=obj.get('amount');currency=str(obj.get('currency','')).upper();ref=obj.get('reference')
    if not paid and not expired:h.send(200,{'ignored':True});return
    c.execute('BEGIN IMMEDIATE')
    o=c.execute('SELECT * FROM orders WHERE id=? AND tenant_id=? AND gateway=?',(oid,tid,g)).fetchone()
    if not o:h.send(400,{'error':'Unknown order'});return
    order_mode=o['mode']
    if order_mode is None and g=='stripe':
        original_ref=o['provider_ref'] or ''
        order_mode='live' if original_ref.startswith('cs_live_') else 'test' if original_ref.startswith('cs_test_') else None
    if order_mode is None:h.send(400,{'error':'Legacy order requires payment-environment reconciliation'});return
    if order_mode!=verified_mode:h.send(400,{'error':'Payment environment mismatch'});return
    if g=='stripe' and 'livemode' in event and bool(event['livemode'])!=(verified_mode=='live'):h.send(400,{'error':'Payment environment mismatch'});return
    if g=='paystack' and obj.get('domain') in ('test','live') and obj['domain']!=verified_mode:h.send(400,{'error':'Payment environment mismatch'});return
    if not eid or (o['provider_ref'] and o['provider_ref']!=ref):h.send(400,{'error':'Reference mismatch'});return
    if paid and (amount!=o['amount'] or currency!=o['currency']):h.send(400,{'error':'Amount or currency mismatch'});return
    if c.execute('SELECT 1 FROM payment_events WHERE tenant_id=? AND gateway=? AND event_id=?',(tid,g,eid)).fetchone():h.send(200,{'ok':True});return
    c.execute('INSERT INTO payment_events VALUES(?,?,?,?)',(tid,g,eid,time.time()))
    if paid and o['status']=='pending':
        c.execute("UPDATE orders SET status='paid',paid=?,pickup_code=?,provider_ref=COALESCE(provider_ref,?) WHERE id=?",(time.time(),secrets.token_hex(4).upper(),ref,oid))
        c.execute("UPDATE listings SET status='sold' WHERE id=?",(o['listing'],))
    elif expired and o['status']=='pending':
        c.execute("UPDATE orders SET status='expired' WHERE id=?",(oid,))
        c.execute("UPDATE listings SET status='available' WHERE id=? AND status='reserved'",(o['listing'],))
    h.send(200,{'ok':True})
