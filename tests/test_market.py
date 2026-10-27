import unittest,tempfile,os,sys,threading,json,urllib.request,urllib.error
sys.path.insert(0,os.path.dirname(os.path.dirname(__file__)))
os.environ['NEARMARKET_DATA']=tempfile.mkdtemp()
import app
class Market(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  app.init();cls.s=app.ThreadingHTTPServer(('127.0.0.1',0),app.Handler);threading.Thread(target=cls.s.serve_forever,daemon=True).start()
 @classmethod
 def tearDownClass(cls):cls.s.shutdown();cls.s.server_close()
 def req(self,path,data=None,cookie='',key='',tenant=1):
  req=urllib.request.Request('http://127.0.0.1:'+str(self.s.server_port)+'/api/'+path,data=json.dumps(data).encode() if data is not None else None,headers={'Content-Type':'application/json','Cookie':cookie,'Authorization':'Bearer '+key,'X-Tenant-ID':str(tenant)})
  try:
   with urllib.request.urlopen(req) as r:return r.status,json.load(r),r.headers.get('Set-Cookie','').split(';')[0]
  except urllib.error.HTTPError as e:return e.code,json.load(e),''
 def test_admin_gui_routes_and_role_activation(self):
  import subprocess
  for path in ('/admin','/admin/api-keys','/admin/api','/admin/keys','/admin/payment-gateways'):
   with urllib.request.urlopen('http://127.0.0.1:'+str(self.s.server_port)+path) as response:
    self.assertEqual(response.status,200)
    self.assertIn('text/html',response.headers['Content-Type'])
    self.assertEqual(response.headers['Cache-Control'],'no-store')
    self.assertIn('id="apiKeys" hidden',response.read().decode())
  self.assertEqual(self.req('admin')[0],403)
  _,u,cookie=self.req('signup',{'name':'GUI Owner','email':'guiowner@example.com','password':'longpassword123'})
  self.assertEqual(self.req('admin',{'action':'create_key','name':'Unauthorized','scopes':['listings:read'],'days':30},cookie)[0],403)
  cli=subprocess.run([sys.executable,app.__file__,'--promote-admin','guiowner@example.com'],capture_output=True,text=True,check=True)
  self.assertIn('/admin/api-keys',cli.stdout)
  self.assertEqual(self.req('me',cookie=cookie)[1]['role'],'superadmin')
  self.assertEqual(self.req('admin',cookie=cookie)[0],200)
  subprocess.run([sys.executable,app.__file__,'--promote-admin','guiowner@example.com'],capture_output=True,text=True,check=True)
  with app.db() as c:
   self.assertEqual(c.execute("SELECT count(*) FROM audit WHERE action='bootstrap:promote-admin' AND target=?",(str(u['id']),)).fetchone()[0],1)
 def test_gateway_admin_secrets_permissions_and_modes(self):
  from unittest.mock import patch
  from cryptography.fernet import Fernet
  import gateway_admin,payments
  _,admin_user,admin=self.req('signup',{'name':'Gateway Admin','email':'gatewayadmin@example.com','password':'longpassword123'})
  _,member,buyer=self.req('signup',{'name':'Gateway Member','email':'gatewaymember@example.com','password':'longpassword123'})
  with app.db() as c:
   c.execute("UPDATE users SET role='superadmin' WHERE id=?",(admin_user['id'],))
   tid=c.execute("INSERT INTO tenants(name,slug,created) VALUES('Gateway market','gateway-market',0)").lastrowid
   c.execute("INSERT INTO memberships VALUES(?,?,'admin')",(tid,member['id']))
  self.assertEqual(self.req('admin/gateways')[0],403)
  self.assertEqual(self.req('admin/gateways',cookie=buyer,tenant=tid)[0],403)
  payload={'action':'save','tenant_id':tid,'gateway':'stripe','mode':'test','secret':'sk_test_fixtureGateway123','webhook_secret':'whsec_fixtureGateway123','public_key':'pk_test_fixtureGateway123','label':'Sandbox','payments_enabled':True,'enabled':True,'allow_live':False,'current_password':'longpassword123'}
  self.assertEqual(self.req('admin/gateways',payload,buyer,tenant=tid)[0],403)
  with tempfile.TemporaryDirectory() as root:
   key=os.path.join(root,'gateway.key')
   from pathlib import Path
   Path(key).write_bytes(Fernet.generate_key())
   with patch.dict(os.environ,{'NEARMARKET_GATEWAY_KEY_FILE':key,'NEARMARKET_ALLOW_LIVE_PAYMENTS':'0'}):
    self.assertEqual(self.req('admin/gateways',{**payload,'current_password':'wrong'},admin)[0],403)
    self.assertEqual(self.req('admin/gateways',payload,admin)[0],200)
    response=self.req('admin/gateways',cookie=admin)[1]
    encoded=json.dumps(response);self.assertNotIn(payload['secret'],encoded);self.assertNotIn(payload['webhook_secret'],encoded)
    record=next(t for t in response['tenants'] if t['id']==tid)
    self.assertTrue(record['gateways']['stripe']['ready'])
    with app.db() as c:
     row=c.execute("SELECT * FROM gateway_configs WHERE tenant_id=? AND gateway='stripe' AND mode='test'",(tid,)).fetchone()
     self.assertNotIn(payload['secret'],json.dumps(dict(row)))
     dump='\n'.join(c.iterdump())
     self.assertNotIn(payload['secret'],dump);self.assertNotIn(payload['webhook_secret'],dump)
     t=dict(c.execute('SELECT * FROM tenants WHERE id=?',(tid,)).fetchone())
    self.assertEqual(gateway_admin.read_secret(tid,'stripe',mode='test'),payload['secret'])
    paystack={**payload,'gateway':'paystack','secret':'sk_test_paystackFixture123','webhook_secret':'','public_key':'pk_test_paystackFixture123'}
    self.assertEqual(self.req('admin/gateways',paystack,admin)[0],200)
    self.assertEqual(gateway_admin.read_secret(tid,'paystack',mode='test'),paystack['secret'])
    self.assertEqual(self.req('admin/gateways',{**payload,'mode':'live','secret':'','webhook_secret':''},admin)[0],400)
    with patch.object(gateway_admin,'provider_check',return_value=(True,'API connection verified')) as check:
     self.assertTrue(self.req('admin/gateways',{'action':'check','tenant_id':tid,'gateway':'stripe','mode':'test','current_password':'longpassword123'},admin)[1]['ok'])
     self.assertEqual(check.call_args.args[1],payload['secret'])
    live={**payload,'mode':'live','secret':'sk_live_fixtureGateway123','webhook_secret':'whsec_fixtureLive12345','public_key':'pk_live_fixtureGateway123','allow_live':True}
    self.assertEqual(self.req('admin/gateways',live,admin)[0],200)
    self.assertFalse(payments.gateway_status(t)['stripe']['ready'])
    with patch.dict(os.environ,{'NEARMARKET_ALLOW_LIVE_PAYMENTS':'1'}):self.assertTrue(payments.gateway_status(t)['stripe']['ready'])
    self.assertEqual(gateway_admin.read_secret(tid,'stripe',mode='test'),payload['secret'])
    # Switching active mode does not stop authenticated test-mode webhook verification.
    import hmac,hashlib,time
    raw=b'{}';stamp=str(int(time.time()));digest=hmac.new(payload['webhook_secret'].encode(),stamp.encode()+b'.'+raw,hashlib.sha256).hexdigest()
    self.assertTrue(payments.signature('stripe',raw,{'Stripe-Signature':f't={stamp},v1={digest}'},t,'test'))
    self.assertFalse(payments.signature('stripe',raw,{'Stripe-Signature':f't={stamp},v1={digest}'},t,'live'))
    self.assertEqual(self.req('admin/gateways',{'action':'clear','tenant_id':tid,'gateway':'stripe','mode':'live','current_password':'longpassword123'},admin)[0],200)
    with patch.dict(os.environ,{f'NEARMARKET_T{tid}_STRIPE_SECRET':'sk_live_environment123',f'NEARMARKET_T{tid}_STRIPE_WEBHOOK_SECRET':'whsec_environment123'}):
     self.assertEqual(gateway_admin.read_secret(tid,'stripe',mode='live'),'')
     self.assertEqual(self.req('admin/gateways',{'action':'import','tenant_id':tid,'gateway':'stripe','mode':'live','current_password':'longpassword123'},admin)[0],200)
     self.assertEqual(gateway_admin.read_secret(tid,'stripe',mode='live'),'sk_live_environment123')
    # Ciphertext is authenticated to its tenant, gateway, field and environment.
    with app.db() as c:
     cipher=c.execute("SELECT secret_cipher FROM gateway_configs WHERE tenant_id=? AND gateway='stripe' AND mode='test'",(tid,)).fetchone()[0]
     c.execute("UPDATE gateway_configs SET secret_cipher=? WHERE tenant_id=? AND gateway='stripe' AND mode='live'",(cipher,tid))
    with self.assertRaises(ValueError):gateway_admin.read_secret(tid,'stripe',mode='live')
    with patch.dict(os.environ,{'NEARMARKET_GATEWAY_KEY_FILE':os.path.join(root,'missing')}):
     self.assertEqual(self.req('admin/gateways',payload,admin)[0],400)
    # Reauthentication is throttled independently from normal sign-in.
    for i in range(5):self.assertEqual(self.req('admin/gateways',{**payload,'current_password':'wrong'},admin)[0],403)
    self.assertEqual(self.req('admin/gateways',payload,admin)[0],429)
 def test_location_radius_defaults_overrides_and_privacy(self):
  import math,trade_locations
  from unittest.mock import patch
  _,boss,a=self.req('signup',{'name':'Radius Admin','email':'radiusadmin@example.com','password':'longpassword123'})
  _,seller,s=self.req('signup',{'name':'Radius Seller','email':'radiusseller@example.com','password':'longpassword123'})
  _,buyer,b=self.req('signup',{'name':'Radius Buyer','email':'radiusbuyer@example.com','password':'longpassword123'})
  with app.db() as c:c.execute("UPDATE users SET role='superadmin' WHERE id=?",(boss['id'],))
  self.req('tenant/admin',{'action':'create','name':'Radius Market','slug':'radius-market','owner':'radiusseller@example.com','public':True},a)
  with app.db() as c:tid=c.execute("SELECT id FROM tenants WHERE slug='radius-market'").fetchone()[0]
  self.req('tenant/join',{},b,tenant=tid)
  lon=lambda miles:math.degrees(miles*trade_locations.MI_TO_KM/6371)
  state=self.req('location-settings',cookie=b,tenant=tid)[1]
  self.assertAlmostEqual(state['policy']['default_buy_km'],60*1.609344)
  self.assertEqual(self.req('admin/locations',cookie=s,tenant=tid)[0],403)
  item={'title':'Radius test chair','description':'Chair available within the local sales area','price':50,'currency':'USD','category':'Furniture','condition':'Good','area':'Neighborhood','lat':0,'lon':0,'private_address':'Private pickup address, not public','online':True}
  code,l,_=self.req('listings',item,s,tenant=tid);self.assertEqual(code,201)
  lid=l['id']
  self.assertEqual(self.req('listings',cookie=b,tenant=tid)[1],[])
  within=self.req('listings?lat=0&lon='+str(lon(59.9)),cookie=b,tenant=tid)[1]
  self.assertEqual(len(within),1);self.assertAlmostEqual(within[0]['sell_radius_km'],96.56064)
  self.assertNotIn('private_location',within[0]);self.assertNotIn('Private pickup address',json.dumps(within))
  self.assertEqual(self.req('listings?lat=0&lon='+str(lon(60.1)),cookie=b,tenant=tid)[1],[])
  mine=self.req('listings?mine=1',cookie=s,tenant=tid)[1]
  self.assertEqual(mine[0]['private_location']['label'],item['private_address'])
  other={**item,'title':'Precise private location','lat':10.123456,'lon':20.654321}
  self.assertEqual(self.req('listings',other,s,tenant=tid)[0],201)
  public=self.req('listings?lat=10.123456&lon=20.654321',cookie=b,tenant=tid)[1][0]
  self.assertEqual(public['lat'],10.12);self.assertEqual(public['lon'],20.65);self.assertNotIn('private_location',public)
  self.assertEqual(self.req('location-settings',{'kind':'buy','label':'My private address','lat':0,'lon':lon(30),'radius':20,'unit':'mi','use_current':False},b,tenant=tid)[0],200)
  self.assertEqual(self.req('listings',cookie=b,tenant=tid)[1],[])
  self.assertEqual(len(self.req('listings?radius=40&unit=mi',cookie=b,tenant=tid)[1]),1)
  edit={**item,'listing':lid,'sell_radius':10,'sell_radius_unit':'mi'}
  self.assertEqual(self.req('edit',edit,s,tenant=tid)[0],200)
  self.assertEqual(self.req('listings?lat=0&lon='+str(lon(10.1))+'&radius=60&unit=mi',cookie=b,tenant=tid)[1],[])
  self.assertEqual(self.req('messages',{'listing':lid,'body':'Can I buy this?','offer':40,'lat':0,'lon':lon(11)},b,tenant=tid)[0],400)
  self.assertEqual(self.req('messages',{'listing':lid,'body':'Can I buy this?','offer':40,'lat':0,'lon':lon(9)},b,tenant=tid)[0],200)
  # Super admins can lock a user center/radius, and ordinary users cannot override it.
  self.assertEqual(self.req('admin/locations',{'action':'user','user_id':buyer['id'],'kind':'buy','label':'Assigned area','lat':0,'lon':0,'radius':5,'unit':'mi','locked':True,'use_current':False},a,tenant=tid)[0],200)
  self.assertEqual(self.req('location-settings',{'kind':'buy','label':'Override','lat':0,'lon':0,'radius':100,'unit':'mi'},b,tenant=tid)[0],400)
  with app.db() as c:
   t=c.execute('SELECT * FROM tenants WHERE id=?',(tid,)).fetchone();row=c.execute('SELECT * FROM listings WHERE id=?',(lid,)).fetchone()
   # Checkout uses unrounded distances and the locked account policy, even if coordinates are forged.
   trade_locations.require_purchase(c,t,buyer,row,{'lat':0,'lon':lon(999),'radius':100})
   self.assertAlmostEqual(trade_locations.radius(60,'mi'),96.56064)
   with self.assertRaises(ValueError):trade_locations.radius(float('nan'))
  # Marketplace boundaries are enforced on listing writes, not just by the frontend.
  policy={'action':'policy','default_buy_km':96.56064,'default_sell_km':96.56064,'max_buy_km':500,'max_sell_km':500,'center_lat':0,'center_lon':0,'market_radius_km':20,'restrict_marketplace':True,'area_label':'Local zone'}
  self.assertEqual(self.req('admin/locations',policy,a,tenant=tid)[0],200)
  self.assertEqual(self.req('listings',{**item,'lon':lon(20)},s,tenant=tid)[0],400)
  self.assertEqual(self.req('geocode',{'address':'An address'},b,tenant=tid)[0],400)
  with patch.dict(os.environ,{'NEARMARKET_GEOAPIFY_KEY':'fixtureGeoapifyKey123'}),patch.object(trade_locations,'lookup',return_value=[{'lat':0,'lon':0,'label':'Example address','area':'Town'}]) as geocoder:
   self.assertEqual(self.req('geocode',{'address':'Example address'},b,tenant=tid)[0],200)
   self.assertEqual(self.req('geocode',{'address':'Example address'},b,tenant=tid)[0],200)
   self.assertEqual(geocoder.call_count,1)
 def test_radius_math_and_current_gps_checkout(self):
  import trade_locations
  self.assertAlmostEqual(trade_locations.distance(0,179.9,0,-179.9),22.2389853289,places=5)
  self.assertAlmostEqual(trade_locations.radius(60,'mi'),96.56064)
  for value in ('nan','inf',-1,0):
   with self.assertRaises(ValueError):trade_locations.radius(value)
  _,u,cookie=self.req('signup',{'name':'GPS Buyer','email':'gpsbuyer@example.com','password':'longpassword123'})
  self.req('location-settings',{'kind':'buy','label':'GPS origin','lat':0,'lon':0,'radius':60,'unit':'mi','use_current':True},cookie)
  with app.db() as c:
   t=c.execute('SELECT * FROM tenants WHERE id=1').fetchone()
   listing={'id':9999999,'lat':0,'lon':0}
   with self.assertRaises(ValueError):trade_locations.require_purchase(c,t,u,listing,{})
   trade_locations.require_purchase(c,t,u,listing,{'lat':0,'lon':0})
   with self.assertRaises(ValueError):trade_locations.require_purchase(c,t,u,listing,{'lat':0,'lon':2})
 def test_permissions_and_marketplace(self):
  _,u,s=self.req('signup',{'name':'Seller','email':'s@example.com','password':'longpassword123'})
  _,v,b=self.req('signup',{'name':'Buyer','email':'b@example.com','password':'longpassword123'})
  d={'title':'Reading chair','description':'Comfortable used chair','price':50,'currency':'USD','category':'Furniture','condition':'Good','area':'Dallas','lat':32.78,'lon':-96.8,'image':''}
  code,l,_=self.req('listings',d,s);self.assertEqual(code,201)
  self.assertEqual(len(self.req('listings?lat=32.78&lon=-96.8&radius=5')[1]),1)
  self.assertEqual(self.req('listings?lat=0&lon=0&radius=5')[1],[])
  self.assertEqual(self.req('status',{'listing':l['id'],'status':'sold'},b)[0],400)
  self.assertEqual(self.req('messages',{'listing':l['id'],'body':'Still available?','offer':45,'lat':32.78,'lon':-96.8},b)[0],200)
  self.assertEqual(len(self.req('messages',cookie=s)[1]),1)
  self.assertEqual(self.req('admin',cookie=b)[0],403)
  with app.db() as c:c.execute("UPDATE users SET role='superadmin' WHERE id=?",(u['id'],))
  code,k,_=self.req('admin',{'action':'create_key','name':'Test key','scopes':['listings:read'],'days':30},s);self.assertEqual(code,200)
  secret=k['secret'];self.assertEqual(self.req('v1/listings',key=secret)[0],200)
  self.assertEqual(self.req('v1/listings',{**d,'seller':u['id']},key=secret)[0],403)
  a=self.req('admin',cookie=s)[1];self.assertNotIn(secret,json.dumps(a));self.assertNotIn('key_hash',a['keys'][0])
  self.req('admin',{'action':'revoke_key','id':a['keys'][0]['id']},s)
  self.assertEqual(self.req('v1/listings',key=secret)[0],401)
  self.req('admin',{'action':'user','id':v['id'],'role':'user','disabled':True},s)
  self.assertIsNone(self.req('me',cookie=b)[1])
  self.assertEqual(self.req('admin',{'action':'user','id':u['id'],'role':'user'},s)[0],400)
 def test_z_tenants_payments_and_key_controls(self):
  from unittest.mock import patch
  import time,hmac,hashlib
  _,owner,admin=self.req('signup',{'name':'Tenant Owner','email':'owner@example.com','password':'longpassword123'})
  _,buyer,b=self.req('signup',{'name':'Tenant Buyer','email':'tenantbuyer@example.com','password':'longpassword123'})
  with app.db() as c:c.execute("UPDATE users SET role='superadmin' WHERE id=?",(owner['id'],))
  self.assertEqual(self.req('tenant/admin',{'action':'create','name':'Private Market','slug':'private-market','owner':'owner@example.com','public':False},admin)[0],200)
  with app.db() as c:tid=c.execute("SELECT id FROM tenants WHERE slug='private-market'").fetchone()[0]
  self.assertEqual(self.req('listings',cookie=b,tenant=tid)[0],403)
  self.assertEqual(self.req('tenant/join',{},b,tenant=tid)[0],403)
  self.assertEqual(self.req('tenant/admin',{'action':'member','email':'tenantbuyer@example.com','role':'member'},admin,tenant=tid)[0],200)
  d={'title':'Tenant chair','description':'A chair in private market','price':50,'currency':'USD','category':'Furniture','condition':'Good','area':'Dallas','lat':32.78,'lon':-96.8,'online':True}
  code,l,_=self.req('listings',d,admin,tenant=tid);self.assertEqual(code,201)
  self.assertEqual(len(self.req('listings?lat=32.78&lon=-96.8',cookie=b,tenant=tid)[1]),1)
  self.assertNotIn(l['id'],[r['id'] for r in self.req('listings')[1]])
  self.assertEqual(self.req('messages',{'listing':l['id'],'body':'Hello'},b)[0],400)
  self.assertEqual(self.req('tenant/admin',cookie=b,tenant=tid)[0],403)
  _,k,_=self.req('admin',{'action':'create_key','name':'Tenant integration','scopes':['listings:read'],'days':5,'rpm':1,'tenant_id':tid},admin)
  self.assertEqual(self.req('v1/listings',key=k['secret'])[0],403)
  self.assertEqual(self.req('v1/listings',key=k['secret'],tenant=tid)[0],200)
  self.assertEqual(self.req('v1/listings',key=k['secret'],tenant=tid)[0],429)
  keys=self.req('admin',cookie=admin)[1]['keys'];kid=next(x['id'] for x in keys if x['name']=='Tenant integration')
  _,rot,_=self.req('admin',{'action':'rotate_key','id':kid},admin)
  self.assertEqual(self.req('v1/listings',key=k['secret'],tenant=tid)[0],401)
  self.assertNotIn(rot['secret'],json.dumps(self.req('admin',cookie=admin)[1]))
  self.req('admin',{'action':'api_toggle','enabled':False},admin)
  self.assertEqual(self.req('v1/listings',key=rot['secret'],tenant=tid)[0],503)
  self.req('admin',{'action':'api_toggle','enabled':True},admin)
  self.req('tenant/admin',{'action':'settings','name':'Private Market','public':False,'listing_limit':10,'payments':True,'stripe':True,'paystack':False},admin,tenant=tid)
  env={f'NEARMARKET_T{tid}_STRIPE_SECRET':'sk_test_fixture',f'NEARMARKET_T{tid}_STRIPE_WEBHOOK_SECRET':'whsec_fixture','NEARMARKET_PUBLIC_URL':'https://market.example'}
  with patch.dict(os.environ,env),patch('payments.checkout',return_value=('cs_test_fixture','https://checkout.stripe.com/c/test_fixture')):
   code,o,_=self.req('checkout',{'listing':l['id'],'gateway':'stripe','lat':32.78,'lon':-96.8},b,tenant=tid);self.assertEqual(code,201)
   self.assertEqual(self.req('checkout',{'listing':l['id'],'gateway':'stripe','lat':32.78,'lon':-96.8},b,tenant=tid)[0],400)
   self.assertEqual(self.req('status',{'listing':l['id'],'status':'available'},admin,tenant=tid)[0],400)
   def hook(event,valid=True):
    raw=json.dumps(event).encode();stamp=str(int(time.time()));sig=hmac.new(b'whsec_fixture',stamp.encode()+b'.'+raw,hashlib.sha256).hexdigest()
    req=urllib.request.Request('http://127.0.0.1:'+str(self.s.server_port)+f'/api/webhooks/stripe/{tid}',data=raw,headers={'Stripe-Signature':f't={stamp},v1={sig if valid else "bad"}'})
    try:
     with urllib.request.urlopen(req) as r:return r.status
    except urllib.error.HTTPError as e:return e.code
   event={'id':'evt_fixture','type':'checkout.session.completed','data':{'object':{'id':'cs_test_fixture','payment_status':'paid','amount_total':5000,'currency':'usd','metadata':{'order_id':o['id']}}}}
   self.assertEqual(hook(event,False),400)
   event['data']['object']['amount_total']=1;self.assertEqual(hook(event),400)
   event['data']['object']['amount_total']=5000;self.assertEqual(hook(event),200);self.assertEqual(hook(event),200)
   rows=self.req('orders',cookie=b,tenant=tid)[1];self.assertEqual(rows[0]['status'],'paid')
   pickup=rows[0]['pickup_code'];self.assertTrue(pickup)
   self.assertNotIn('pickup_code',self.req('orders',cookie=admin,tenant=tid)[1][0])
   self.assertEqual(self.req('orders/pickup',{'order':o['id'],'code':pickup},b,tenant=tid)[0],403)
   self.assertEqual(self.req('orders/pickup',{'order':o['id'],'code':'WRONG'},admin,tenant=tid)[0],400)
   self.assertEqual(self.req('orders/pickup',{'order':o['id'],'code':pickup},admin,tenant=tid)[0],200)
   self.assertEqual(self.req('orders/dispute',{'order':o['id'],'reason':'The chair was damaged at pickup'},b,tenant=tid)[0],200)
   self.assertEqual(self.req('orders/resolve',{'order':o['id'],'resolution':'Seller has arranged a replacement'},b,tenant=tid)[0],403)
   self.assertEqual(self.req('orders/resolve',{'order':o['id'],'resolution':'Seller has arranged a replacement'},admin,tenant=tid)[0],200)
   self.assertEqual(self.req('orders',cookie=b)[1],[])
   with app.db() as c:
    self.assertEqual(c.execute('SELECT status FROM listings WHERE id=?',(l['id'],)).fetchone()[0],'sold')
    self.assertEqual(c.execute('SELECT count(*) FROM payment_events WHERE tenant_id=?',(tid,)).fetchone()[0],1)
  # Tenant managers can administer their own marketplace, never global keys/users.
  self.req('tenant/admin',{'action':'member','email':'tenantbuyer@example.com','role':'admin'},admin,tenant=tid)
  self.assertEqual(self.req('tenant/admin',cookie=b,tenant=tid)[0],200)
  self.assertEqual(self.req('admin',cookie=b,tenant=tid)[0],403)
  self.req('tenant/admin',{'action':'suspend','id':tid,'active':False},admin)
  self.assertEqual(self.req('listings',cookie=b,tenant=tid)[0],400)
 def test_gateway_adapters_and_signatures(self):
  import payments,hmac,hashlib
  from unittest.mock import patch
  t={'id':99,'payments':1,'stripe':1,'paystack':1}
  env={'NEARMARKET_T99_STRIPE_SECRET':'sk_test_fixture','NEARMARKET_T99_STRIPE_WEBHOOK_SECRET':'whsec_fixture','NEARMARKET_T99_PAYSTACK_SECRET':'sk_test_fixture','NEARMARKET_PUBLIC_URL':'https://market.example'}
  o={'id':'nmorder_fixture','amount':10000,'currency':'NGN'}
  with patch.dict(os.environ,env):
   with patch('payments.provider_post',return_value={'id':'cs_fixture','url':'https://checkout.stripe.com/c/fixture'}) as post:
    ref,url=payments.checkout(t,'stripe',o,'b@example.com','Chair')
    self.assertEqual(ref,'cs_fixture');self.assertEqual(post.call_args.args[1]['line_items[0][price_data][unit_amount]'],10000)
   with patch('payments.provider_post',return_value={'status':True,'data':{'reference':o['id'],'authorization_url':'https://checkout.paystack.com/fixture'}}) as post:
    ref,url=payments.checkout(t,'paystack',o,'b@example.com','Chair')
    self.assertEqual(post.call_args.args[1]['reference'],o['id'])
   raw=b'{"event":"charge.success"}'
   digest=hmac.new(b'sk_test_fixture',raw,hashlib.sha512).hexdigest()
   self.assertTrue(payments.signature('paystack',raw,{'x-paystack-signature':digest},t))
   self.assertFalse(payments.signature('paystack',raw+b' ',{'x-paystack-signature':digest},t))
   with patch.dict(os.environ,{'NEARMARKET_T99_STRIPE_SECRET':'sk_live_fixture','NEARMARKET_ALLOW_LIVE_PAYMENTS':'0'}):self.assertFalse(payments.gateway_status(t)['stripe']['ready'])
 def test_existing_database_migration_is_repeatable(self):
  app.init();app.init()
  with app.db() as c:
   self.assertIn('tenant_id',{r[1] for r in c.execute('PRAGMA table_info(listings)')})
   self.assertIn('rpm',{r[1] for r in c.execute('PRAGMA table_info(api_keys)')})
if __name__=='__main__':unittest.main()
