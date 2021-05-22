import time
import urllib2
from pprint import pprint
from zapv2 import ZAPv2

# The value of api must match api.key when running the daemon
api = "hleklpcvllg77l6dft5e5p04o3"

myApp = 'https://${172.31.1.86}/'

#The following line must be the ip of where ZAP is, so for us it is localhost:8090
#Also if you are not running ZAP on port 8080 then you must include the line below 
#with the correct port numbers.

#zap = ZAPv2(proxies={'http': 'http://localhost:${port}', 'https': 'http://localhost:${port}'})
zap = ZAPv2(proxies={'http': 'https://stackoverflow.com/', 'https': 'https://stackoverflow.com/'})
# The script must be loaded prior to importing the context otherwise it will fail.

# Additionally, the APIKEY must be the last parameter on every method.

# Importing the context using the full file path.

print("IMPORTING CONTEXT")

#zap.context.import_context('${workspace}/sbir-security/sbir.context', apikey = api)
zap.context.import_context('${/usr/lib/python2.7/site-packages/zapv2/}/sbir-security/sbir.context', apikey = api)

# The URL must be opened before it can be tested on.

print('Accessing target %s' % myApp)

zap.urlopen(myApp)

time.sleep(2)

# Start the spider and wait until it's complete

print ('Spidering target ' + myApp)

scanid = zap.spider.scan_as_user(2, 2, myApp, subtreeonly = False, recurse = True, apikey = api)

time.sleep(2)

while (int(zap.spider.status(scanid)) < 100):
    print 'Spider progress %: ' + zap.spider.status(scanid)
    time.sleep(2)

print 'Spider completed'

# Wait for passive scanning to complete

while (int(zap.pscan.records_to_scan) > 0):
  print ('Records to passive scan : ' + zap.pscan.records_to_scan)
  time.sleep(2)

print ('Passive scanning complete')

# Start the active scan and wait till it's complete

print ('Scanning target ' + myApp)

ascan_id = zap.ascan.scan(myApp)

while (int(zap.ascan.status(ascan_id)) < 100):
    print ('Scan progress %: ' + zap.ascan.status(ascan_id))
    time.sleep(5)

print ('Scan completed')

# Report the results

print ('Hosts: ' + ', '.join(zap.core.hosts))
print ('Sites: ' + ', '.join(zap.core.sites))
print ('Urls: ' + ', '.join(zap.core.urls))
print ('Alerts: ')

pprint (zap.core.alerts())

# Writes the XML and HTML reports that will be exported to the workspace.
f = open('${workspace}/xmlreport.xml','w')
f2 = open('${workspace}/htmlreport.html','w')
f.write(zap.core.xmlreport(apikey = api))
f2.write(zap.core.htmlreport(apikey = api))

f.close()
f2.close()
