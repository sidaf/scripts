#!/usr/bin/env python2

# Source: https://github.com/strawp/random-scripts/blob/master/sendmails.py

#################################################################################################################
# Send an HTML email to all addresses in a txt file
#################################################################################################################

import argparse, sys, smtplib, datetime, re, os, random, base64, time, subprocess, csv #, html2text
from email import Encoders
from email.MIMEBase import MIMEBase
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText 
from email.mime.image import MIMEImage

varnames = ['email','name','fname','lname','user']
markers = []
markers.extend(varnames)
markers.extend(['date','b64email','b64remail','randomint'])

parser = argparse.ArgumentParser(description="Send emails with various helpful options")
parser.add_argument("-e", "--emails", help="File containing list of email addresses")
parser.add_argument("-E", "--email", help="Single email address to send to")
parser.add_argument("--csv", help="CSV file of email addresses with headers containing at least 'email' and optionally also: '"+"', '".join(varnames)+"'")
parser.add_argument("-b", "--body", help="File containing HTML body of email, can contain template markers to be replaced with each email sent: {"+"}, {".join(markers)+"}")
parser.add_argument("-B", "--bodydir", help="Directory containing any number of .html files which will be cycled through (different template for each email) to act as the body template")
parser.add_argument("--dtformat", default="%d/%m/%Y", help="Format string for using when substituting {date} in templates")
parser.add_argument("-t", "--text", action="store_true", help="Add a plain text part to the email converted from the HTML body (use if the target mail client doesn't display HTML inline, e.g. IBM Notes might not)")
parser.add_argument("-T", "--textfile", help="Add a plain text part to the email taken from the specified text file") 
parser.add_argument("-s", "--subject", help="Subject line of email")
parser.add_argument("-f", "--fromheader", help="From address (address or 'name <address>')")
parser.add_argument("-r", "--readreceipt", help="Read receipt address (same format as from/to headers")
parser.add_argument("-H", "--header", action="append", help="Add any number of custom headers")
parser.add_argument("-g", "--host", help="SMTP host")
parser.add_argument("-P", "--port", help="SMTP port")
parser.add_argument("-u", "--username", help="SMTP username")
parser.add_argument("-p", "--password", help="SMTP password")
parser.add_argument("-d", "--delay", help="Delay between mail sends (seconds)")
parser.add_argument("--reconnect", default=5, type=int, help="Reconnect to SMTP host after this many email sends")
parser.add_argument("-a", "--attachment", help="Filename to add as an attachment")
parser.add_argument("-x", "--execute", action="append", help="Execute this command before sending each email (stack to create complex commands, e.g. -x 'script.sh' -x 'Email:{email}')")
args = parser.parse_args()

# Switch out place markers for variables
def compile_string(txt, variables ):
  global intsfile
  for name,val in variables.iteritems():
    if type(val) == None: continue
    txt = txt.replace('{'+name+'}', str(val) )

  txt = txt\
    .replace("{date}",datetime.datetime.today().strftime(variables['dtformat']))\
    .replace("{b64email}",base64.b64encode(variables['email']))\
    .replace("{b64remail}",base64.b64encode(variables['email'])[::-1])
  
  randomint = None
  if re.search("{randomint}",txt):
    if not 'randomint' in variables.keys() or not variables['randomint']:
      randomint = random.randint(1,9999999)
      print "Random integer: " + variables['email'] + " : " + str(randomint)
    txt = txt.replace("{randomint}",str(randomint))
    randomints = True
    fp = open(intsfile,"a")
    fp.write(variables['email'] + ":" + str(randomint)+'\n' )
    fp.close()
  return txt, randomint

# Connect to SMTP server
def connect( args ):
  if not args.host:
    server = smtplib.SMTP('localhost')
  else:
    server = smtplib.SMTP(args.host, args.port)
    try:
      server.starttls()
    except:
      print 'Server doesn\'t support STARTTLS'
    server.ehlo()
    if args.username and args.password: 
      server.login(args.username, args.password)
  return server

if not ( args.body or args.bodydir or args.textfile ) or not args.subject or not args.fromheader:
  parser.print_usage()
  sys.exit(2)

if not args.emails and not args.email and not args.csv:
  parser.print_usage()
  sys.exit(2)

if args.host and not args.port:
  args.port = 587

if args.delay:
  args.delay = int( args.delay )

if args.attachment:
  if not os.path.isfile(args.attachment):
    print 'Path to attachment ' + args.attachment + ' not found'

if args.emails:
  emailsfile = args.emails
  print 'Emails file: ', emailsfile
elif args.email:
  print 'Email: ', args.email
elif args.csv:
  print 'CSV: ', args.csv


# Dictionary specific to an email
variables = {}

subject = args.subject
fromheader = args.fromheader

if args.body:
  print 'Body text file: ', args.body
if args.textfile:
  print 'Flat text file: ', args.textfile
print 'Subject: ', subject
print 'From: ', fromheader

namematch = re.compile( "\w{2,}\.\w{2,}" )
attachmentmatch = re.compile( 'src="cid:([^"]+)"' )

# Read in body
if args.body:
  with open (args.body,"r") as file:
    html = file.read() # .replace('\n','')
else:
  html = None

# Read in array of bodies
templates = None
if args.bodydir:
  bd = os.path.expanduser(args.bodydir)
  if not os.path.isdir( bd ):
    print "FAIL: " + bd + " doesn't exist"
  files = [f for f in os.listdir(bd) if os.path.isfile(os.path.join(bd,f))]  # and (re.match('.+\.html$',f) != None ))]
  files = [f for f in files if re.match('.+\.html$',f) != None]
  files.sort()
  templates = []
  for fn in files:
    fn = os.path.join(bd,fn)
    with open(fn,'r') as f:
      templates.append({'name':fn,'content':f.read()})

  if len( templates ) == 0:
    print 'FAIL: No html files found in ' + bd

# Read in flat text
if args.textfile:
  with open(args.textfile,'r') as f:
    text = f.read()
else:
  text = None

# Read in emails
recipients = []
if args.csv:
  with open(args.csv, 'rb') as csvfile:
    csvreader = csv.DictReader(csvfile)
    for row in csvreader:
      if 'email' not in row.keys(): continue
      recipients.append( row )
  
elif args.emails:
  with open(emailsfile) as f:
    emails = f.readlines()
  for email in emails:
    email = email.strip()
    recipients.append({'email':email})
else:
  recipients.append({'email':args.email})

# Connect
server = connect( args )

randomints = False
intsfile = "randomints.txt"
count = 0


# Loop over emails
for variables in recipients:
  
  email = variables['email']
  msg = MIMEMultipart()
  randomint = None

  variables['email'] = email.strip()
  variables['user'] = variables['email'].split('@')[0]
  if 'name' not in variables.keys():
    if namematch.match( variables['user'] ):
      variables['name'] = variables['user'].replace("."," ").title()
    else:
      variables['name'] = ''

  if len(variables['name'].split(' ')) >= 2:
    if 'fname' not in variables.keys(): variables['fname'] = variables['name'].split(' ')[0]
    if 'lname' not in variables.keys(): variables['lname'] = variables['name'].split(' ')[1]
  else:
    if 'fname' not in variables.keys(): variables['fname'] = ''
    if 'lname' not in variables.keys(): variables['lname'] = ''

  variables['dtformat'] = args.dtformat

  if args.execute:
    parts = []
    for x in args.execute:
      x,variables['randomint'] = compile_string(x, variables )
      parts.append(x)
    print 'Running: ' + ' '.join(parts)
    print subprocess.check_output(parts)

  # Compile header
  msg["From"] = fromheader
  msg["To"] = variables['email']
  msg["Subject"],variables['randomint'] = compile_string(subject, variables )
  
  # Read receipt
  if args.readreceipt: 
    print 'Adding read receipt header: ' + args.readreceipt
    msg["Disposition-Notification-To"] = args.readreceipt
  
  # Other custom headers
  if args.header:
    for h in args.header:
      k,v = h.split(':')
      msg[k.strip()] = v.strip()

  bodies = {}

  if html:
    bodies['html'] = html
  if text:
    bodies['text'] = text
  if templates:
    tmpl = templates[count%len(templates)]
    bodies['html'] = tmpl['content']
    print 'Using template: ' + tmpl['name']

  # Compile bodies
  for k,v in bodies.iteritems():
    v,variables['randomint'] = compile_string(v, variables )
    bodies[k] = v

  if 'html' in bodies.keys():
    msg.attach(MIMEText( bodies['html'], "html" ))
    if args.text:
      msg.attach(MIMEText(html2text.html2text(bodies['html']),'plain'))
  
    # Find any embedded images and attach
    attachments = re.findall('src="cid:([^"]+)"',bodies['html'])
    for attachment in attachments:
      fp = open( attachment, "rb" )
      img = MIMEImage(fp.read())
      fp.close()
      img.add_header('Content-ID', attachment )
      msg.attach(img)

  if 'text' in bodies.keys():
    msg.attach(MIMEText(bodies['text'],'plain'))

  # Optional attachment
  if args.attachment:
    filename = os.path.basename( args.attachment )
    part = MIMEBase('application', "octet-stream")
    part.set_payload(open(args.attachment, "rb").read())
    Encoders.encode_base64(part)
    part.add_header('Content-Disposition', 'attachment; filename="'+filename+'"')
    msg.attach(part)

  # print msg.as_string()

  # Send email
  sys.stdout.write( "Sending to " + variables['email'] + "... " )
  sys.stdout.flush()
  server.sendmail( fromheader, variables['email'], msg.as_string() )
  sys.stdout.write( "sent ["+datetime.datetime.today().strftime('%Y-%m-%d %H:%M:%S')+"]\n" )
  sys.stdout.flush()

  if args.delay:
    time.sleep(args.delay)
  count += 1 
  if count % int(args.reconnect) == 0:
    print 'Getting new connection...'
    server = connect( args )
	
server.quit()

if randomints:
  print "Assigned random ints saved to " + intsfile
