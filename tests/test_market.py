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
 def req(self,path,data=None,cookie='',key=''):
  req=urllib.request.Request('http://127.0.0.1:'+str(self.s.server_port)+'/api/'+path,data=json.dumps(data).encode() if data is not None else None,headers={'Content-Type':'application/json','Cookie':cookie,'Authorization':'Bearer '+key})
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
if __name__=='__main__':unittest.main()
