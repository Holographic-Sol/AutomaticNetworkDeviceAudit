#Network Device Audit by Benjamin Jack Cullen

import os
import re
import sys
import csv
import time
import datetime
import codecs
import subprocess
import distutils.dir_util
import fileinput
from colorama import Fore, Back, Style
mainDir = os.path.join(os.path.expanduser('~'),'NetworkDeviceAudit/')
distutils.dir_util.mkpath(mainDir)
config = (mainDir+'/nda.conf')
hostList = (mainDir+'/hostList.xml')
hostDetail = (mainDir+'/hostDetail')
detailTemp = (mainDir+'/detailtmp.tmp')
log = (mainDir+"/logs.log")
startTime = datetime.datetime.now()
iteration=1
complete = []
completeB = []
fnames = []
names = []
configB = []
ip = []
allow = []
q=1
while q==1:
    if os.path.exists(config):
        print('-Reading Configuration File...')
        fo = open(config)
        z=0
        for line in fo.readlines():
            line = line.strip()
            if line not in configB:
                configB.append(line)                
        if len(configB) >= 0:
            a=0
            for configBs in configB:
                if configB[a].startswith('TARGET: '):
                    ip.append(configB[a])
                    ip[a] = ip[a].replace('TARGET: ', '')
                a+=1
            b=0
            for configBs in configB:
                if configB[b].startswith('ALLOW: '):
                    configB[b] = configB[b].replace('ALLOW: ', '')
                    if configB[b] not in allow:
                        allow.append(configB[b])    
                b+=1
        subprocess.call('clear', shell=True)
        print('')
        print(Style.BRIGHT+11*' '+'HIDDEN (IN)SIGHT'+Style.RESET_ALL)
        print(Fore.MAGENTA+3*' '+"_.-=-._"+Style.RESET_ALL+24*" "+Style.BRIGHT+"TIME:"+Fore.YELLOW, datetime.datetime.now(),Style.RESET_ALL)
        print(Fore.MAGENTA+"  --<"+Style.BRIGHT+Fore.YELLOW+"(_)"+Style.RESET_ALL+Fore.MAGENTA+">-"+Style.RESET_ALL+24*" "+Style.BRIGHT+"START-TIME:"+Fore.YELLOW, startTime,Style.RESET_ALL)
        print(Fore.MAGENTA+" *.__.'|"+Style.RESET_ALL+26*" "+Style.BRIGHT+"Scan:"+Fore.YELLOW, iteration,Style.RESET_ALL)
        print(34*' '+Style.BRIGHT+'SCAN TARGET:'+Fore.YELLOW,ip[0],Style.RESET_ALL)
        # Debug START
##        d=0
##        print('conf: ',(len(allow)))
##        for allows in allow:
##            print('conf: ',allow[d])
##            d+=1
##        e=0
##        print('live: ',(len(completeB)))
##        for completeBs in completeB:
##            print('live: ',completeB[e])
##            e+=1
        # /Debug END
        e=0
        for completeBs in completeB:
            data = '  '.join(completeB[e])
            oFile = codecs.open(detailTemp, 'a', encoding='utf-8')
            toFile = (data, '\n')
            oFile.writelines(toFile)
            oFile.close()
            e+=1
        print('')
        if len(completeB) >= 1:
            print(Style.BRIGHT+'Technical Device Information:'+Style.RESET_ALL)
        print('')
        for line in open(detailTemp, 'r'):
            copen = open(config)
            cread = copen.read()
            try:
                if line in cread:
                    print(Style.BRIGHT+Fore.YELLOW,line,Style.RESET_ALL)
                elif line not in cread:
                    print(Style.BRIGHT+Fore.RED,line,Style.RESET_ALL)
                    now = str(datetime.datetime.now())
                    olog = open(log, 'a')
                    toFile = str(now+' ' + line)
                    olog.writelines('Event: '+toFile + '\n')
                olog.close()
            except:
                pass
        iteration += 1
        open(hostList, 'w').close()
        i=0
        print('')
        completeB = []
        allow = []
        print(Style.BRIGHT+'Assertaining Network Device Information:'+Style.RESET_ALL)
        if len(fnames) >= 0:
            for fname in fnames:
                open(fnames[i], 'w').close()
                i+=1
        cmd = ('nmap -sL ' + ip[0] + '/24' + ' -oX ' + hostList)
        print(Style.BRIGHT+Fore.CYAN+'Executing command: '+Fore.YELLOW+cmd+Style.RESET_ALL)
        xcmd = subprocess.Popen(cmd, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print('-Waiting for subprocess to finish...')
        xcmd.wait()
        print ('-Reaping Zombie processes...')
        xcmd.terminate()
        xcmd.communicate()
        if os.path.exists(hostList):
            hostListRead = open(hostList, 'r')
            for line in hostListRead:
                txt = '<hostname name='
                if line.startswith(txt):
                    line = line.strip()
                    line = line[16:]
                    line = line.split('"')[0]
                    print(Style.BRIGHT+'Found Host: '+Fore.YELLOW+line+Style.RESET_ALL+'\r')
                    if line not in names:
                        names.append(line)
            hostListRead.close()
        i=0
        for name in names:
            fname = (str(mainDir+names[i])+'.xml')
            cmd = ('nmap -T4 -v --traceroute ' + names[i] + ' -oX ' + fname)
            print(Style.BRIGHT+Fore.CYAN+'Executing command: '+Fore.YELLOW+cmd+Style.RESET_ALL)
            xcmd = subprocess.Popen(cmd, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            print('-Waiting for subprocess to finish...')
            xcmd.wait()
            print('-Reaping Zombie processes...')
            xcmd.terminate()
            xcmd.communicate()
            i+=1
            if fname not in fnames:
                fnames.append(fname)
        i=0
        for fname in fnames:
            fopen = open(str(fnames[i]), 'r')
            for line in fopen:
                ipaddr = ('<address addr=')
                if line.startswith(ipaddr):
                    address = line.strip()
                    address = address.split()
                    address[1] = address[1].replace('addr=', '')
                    address[1] = address[1].strip('"')
                    if len(address[1]) in range(7, 15):
                        if re.match("[0-9.]*$", address[1]):
                            localip = address[1]
                            fname = fname.strip('.xml')
                            fname = fname.replace(mainDir, '')
                            if fname not in complete:
                                complete.append(fname)
                            if localip not in complete:
                                complete.append(localip)
                    if len(address[1]) == 17:
                        if re.match("[A-Za-z0-9:]*$", address[1]):
                            mac = address[1]
                            fname = fname.strip('.xml')
                            fname = fname.replace(mainDir, '')
                            if mac not in complete:
                                complete.append(mac)
                    if line.find('vendor='):
                        line = line.split('vendor=', 1)[-1]
                        line = line.replace('/', '')
                        line = line.replace('"', '')
                        line = line.replace('>', '')
                        vendor = line
                        vendor = vendor.strip()
                        if line.startswith('<address'):
                            pass
                        else:
                            if vendor not in complete:
                                complete.append(vendor)
                if line.startswith('<port '):
                    portid = line.strip()
                    portid = portid.split()
                    portid[2] = portid[2].replace('portid="', '')
                    portid[2] = portid[2].replace('"><state', '')
                    portid[1] = portid[1].replace('protocol="', '')
                    portid[1] = portid[1].replace('"', '')
                    portid[3] = portid[3].replace('state="', '')
                    portid[3] = portid[3].replace('"', '')
                    portinfo = (portid[2]+'-'+portid[1]+'-'+portid[3])
                    if portinfo not in complete:
                        complete.append(portinfo)
            if len(complete) >= 0:
                if complete not in completeB:
                    completeB.append(complete)
            else:
                pass
            complete = []
            i+=1
        fnames = []
        names = []
        configB = []
        ip = []
        open(detailTemp, 'w').close()
        print('-Restarting...')
    else:
        print('IP UNCONFIGURED')
        q=0
else:
    time.sleep(1)

#To Do
# -Menu configure whitelist arrays
# -Compare live-arrays to whitelist arrays
# -Notify specific activities of interest to HUD/Desktop-Notification
# -Sanitize input. lookup hostname accepted charaters and length & sanitize all other values.

#Improvements:
# -Stability, creating my own parsing formulas has fully stabalized the program over using et.tree module for parsing.
# -Data being compared remains the same, but data is split into arrays for precise notifications, example:
#   unauthorized activity is predicated upon the same data but will now tell you exactly what the activity pertains too,
#   either, hostname, mac, ipv4, ports & services.
#   Before this, you would know there is unauthorized activity occuring but you would have to read the output/log.file to
#   too see exactly what the activity is. But now with all data being split into arrays, the unauthorized activity notifications
#   can be more verbose.
