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
 def test_permissions_and_marketplace(self):
  _,u,s=self.req('signup',{'name':'Seller','email':'s@example.com','password':'longpassword123'})
  _,v,b=self.req('signup',{'name':'Buyer','email':'b@example.com','password':'longpassword123'})
  d={'title':'Reading chair','description':'Comfortable used chair','price':50,'currency':'USD','category':'Furniture','condition':'Good','area':'Dallas','lat':32.78,'lon':-96.8,'image':''}
  code,l,_=self.req('listings',d,s);self.assertEqual(code,201)
  self.assertEqual(len(self.req('listings?lat=32.78&lon=-96.8&radius=5')[1]),1)
  self.assertEqual(self.req('listings?lat=0&lon=0&radius=5')[1],[])
  self.assertEqual(self.req('status',{'listing':l['id'],'status':'sold'},b)[0],400)
  self.assertEqual(self.req('messages',{'listing':l['id'],'body':'Still available?','offer':45},b)[0],200)
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
  self.assertEqual(len(self.req('listings',cookie=b,tenant=tid)[1]),1)
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
   code,o,_=self.req('checkout',{'listing':l['id'],'gateway':'stripe'},b,tenant=tid);self.assertEqual(code,201)
   self.assertEqual(self.req('checkout',{'listing':l['id'],'gateway':'stripe'},b,tenant=tid)[0],400)
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
