#!/usr/bin/python

import json, sys, getopt, os, re

def usage():
  print("Usage: %s --file=[filename]" % sys.argv[0])
  sys.exit()

def main(argv):

  file=''
 
  myopts, args = getopt.getopt(sys.argv[1:], "", ["file="])
 
  for o, a in myopts:
    if o in ('-f, --file'):
      file=a
    else:
      usage()

  if len(file) == 0:
    usage()
 
  corpus = open(file)
  urldata = json.load(corpus, encoding="latin1")


  totalUrls = 0.0
  myMaliciousCount = 0.0
  validMalicious = 0.0
  thresholdMax = 500

  for record in urldata:
    threshold = 0
    totalUrls+=1.0
    malicousBit = 0

    regexDl = re.search("[^(www\.)]google(docs|doc|drive|mail)*",record["url"]) #some variation of google followed by doc or drive
    regexHostIp = re.match("^(\.[0-9][0-9]?[0-9])+$",record["host"]) #only ip host

    if record["scheme"] == "https":
      threshold -= 300

    ext = record["file_extension"]
    if ext in ["zip","php"]:
      threshold += 300
    elif ext == "exe":
      threshold += 1500
    elif ext in ["aspx", "xml"]:
      threshold -= 200

    if record["path_len"] > 30:
      threshold += 200

    if record["malicious_url"]:
      validMalicious+=1.0

    if regexDl:
      threshold += 1000

    if regexHostIp:
      threshold += 300

    domainAge = int(record["domain_age_days"])  #domain age less than half a year
    if domainAge < 180:
      threshold += 800

    alexaRankNotExist = record["alexa_rank"] == None
    if alexaRankNotExist:
      threshold += 1000
    elif int(record["alexa_rank"]) < 1000000:
      threshold -= 200

    #if domainAge or regexDl or alexaRankNotExist or regexHostIp:
    if threshold > thresholdMax:
      myMaliciousCount += 1.0
      malicousBit = 1

    #print (")%s \n \tmalicous: %s") % (record["url"],record["malicious_url"])
    print ("%s, %s") %(record["url"], malicousBit)
    
  print "real malicous: %f" % (validMalicious / totalUrls)
  print "My malicous: %f" % (myMaliciousCount / totalUrls)
  corpus.close()

if __name__ == "__main__":
  main(sys.argv[1:])
