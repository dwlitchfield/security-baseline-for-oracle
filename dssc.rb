# Oracle Security Baseline Assessment Tool
# David Litchfield
# david@davidlitchfield.com

require 'nokogiri'
require 'oci8'
require 'openssl'

$broken = 0

##########################################################
#
#	Write out XML header
#

def StartOutput (host, port, sid, username)
	puts "<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\n<findings>\n"
	puts "<database>"  + host + ":" + port + "/" + sid + "</database>\n"
	puts "<user>" + username + "</user>\n"
	puts "<scantime>" + Time.now.strftime("%d/%m/%Y %H:%m") + "</scantime>\n"
end

##########################################################
#
#	Close XML file
#

def EndOutput
	puts "</findings>\n"
end

##########################################################
#
#	Ensure string replaces all XML metacharacters
#

def MakeXMLSafe (make_this_safe)
	made_safe = make_this_safe.gsub('&', '&amp;')
	made_safe = made_safe.gsub('<', '&lt;')
	made_safe = made_safe.gsub('>', '&gt;')
	made_safe = made_safe.gsub('"', '&quot;')
	return made_safe
end

##########################################################
#
#	Write out an error
#

def WriteError(error)
	puts "<error>" + MakeXMLSafe(error) + "</error>\n</findings>\n"
end

##########################################################
#
#	Connect to the database server
#

def Connect(host, port, sid, username, password)
begin
	connectstring =  "//" + host + ":" + port + "/" + sid
	conn = OCI8.new(username, password, connectstring)
	return conn
end
	rescue Exception => e
		WriteError(e.message)
		return 0
end


##########################################################
#
#	Execute a single data check query and
#	write results
#

def GetData(conn, data_query)
begin
	conn.exec(data_query) { |r1|  puts MakeXMLSafe(r1.join)  }
end
	rescue
end


##########################################################
#
#	Execute a single count check and if 
#	vulnerable execute the data check
#

def ExecuteCheck(conn, query, checks, i)
begin
	conn.exec(query) do |r|
        	if r.to_s.scan(":0").length > 0
                	puts "<finding>\n<check>" + MakeXMLSafe(r.join) + "</check><details>Passed</details></finding>\n"
	        else
			puts "<finding>\n<check>" + MakeXMLSafe(r.join) + "</check>\n"
	                data_query = checks[i].css("data_check").first.content
			details = checks[i].css("details").first.content
			puts "<details>" + MakeXMLSafe(details) + "</details>\n"
                	if data_query.length > 0
				puts "<data>"
		                GetData(conn, data_query)
				puts "</data>\n"
			end
                	puts "</finding>\n"
	        end
	
	end
end
	rescue
end



##########################################################
#
#	Execute a single data check query and
#	write results
#

def DoPwdCheck(conn, data_query, status)
begin
	conn.exec(data_query) { |r1|   GuessPassword(r1.join, status)  }
end
	rescue
end

#####################################
#
#	Print out broken accounts
#

def PrintBroken(username, password, ptime, status)

	if $broken == 0
		print "256</check>"
		$broken = 1
	end

	print "<broken><username>"
	print MakeXMLSafe("#{username}")
	print "</username><password>"
	print MakeXMLSafe("#{password}")
	print "</password><changedate>"
	print MakeXMLSafe("#{ptime}")
	print "</changedate><status>"
	print "#{status}"
	print "</status></broken>\n"
end

#########################################
#
#	GuessPassword
#

def GuessPassword(usernamepassword, status)

	passwordlist = "PASSWORD", "PASSWORD1", "CHANGE_ON_INSTALL", "WELCOME", "CHANGEME", "WELCOME123", "ORACLE", "MANAGER", "SYSTEM", "LETMEIN", "S3CR3T", "SECRET", "PASSW0RD", "MASTER", "DRAGON", "MONKEY", "LOVE", "GOD", "BASEBALL", "12345", "123456", "TEST", "TEST123", "ILOVEYOU", "QWERTY", "1234567", "12345678", "123456789", "ASDFGH", "ASDZXC", "QAZWSX", "ABC123", "ZXCVBNM", "LIZARD", "PIRATE", "DATABASE", "0RACLE", "0RACL3", "DBADBA", "DBA", "ORACLEDBA", "ORADBA", "PLEASECHANGE", "CHANGE", "CHANGENOW", "PASSWORD777", "ABC", "MERCURY", "VENUS", "MARS", "JUPITER", "SATURN", "URANUS", "NEPTUNE", "PLUTO", "COKE", "PEPSI", "JOLT", "SECURITY", "S3CURITY", "OVERRIDE", "POWER", "IAMGOD", "WIZARD", "OPENSESAME"

	

	ind = usernamepassword.index(',')
	dt = usernamepassword.index(':')
	username = usernamepassword[0,ind]
	pwdhash = usernamepassword[ind+1,16]
	ptime = usernamepassword[dt+1..-1]

	c = 0
	testhash = GetPasswordHash(username, username)
	if pwdhash != testhash then
		while(c < passwordlist.count) do
			testhash = GetPasswordHash(username,passwordlist[c])
			if pwdhash == testhash then
				PrintBroken(username, passwordlist[c], ptime, status)
			end
			c+=1
		end
	else
		PrintBroken(username, username, ptime, status)
	end	

end


###############################
#
# OraEncrypt
#

def OraEncrypt (s, key)
	iv = "\x00\x00\x00\x00\x00\x00\x00\x00"
	cipher = OpenSSL::Cipher::Cipher.new("des-cbc")
	cipher.encrypt
	cipher.key = key
	cipher.iv = iv 
	cipher.padding = 0
	ciphertext = cipher.update(s)
	ciphertext << cipher.final
	return ciphertext.bytes
end

###############################
#
# GetNewKey - get last 8 bytes of ciphertext
#

def GetNewKey(x)
	i = x.length - 8
	c = 0
	newkey = Array.new(8)
	while i < x.length do
		newkey[c] = x[i]
		c+=1
		i+=1
	end
	return newkey.pack("CCCCCCCC")
end

###############################
#
# PrepareUsernameAndPassword
#

def PrepareUsernameAndPassword(username, password)
	up = username + password
	xcnt = cnt = up.length * 2

	if cnt % 8 > 0 then
		cnt = cnt + (8 - (cnt % 8))
	end
	byte_array = Array.new(40)
	buf = up.bytes.pack("C*")
	i = 0
	c = 0 
	while i < xcnt do 
		byte_array[i]="\0"
		i+=1
		byte_array[i]=buf[c]
		i+=1
		c+=1
	end
	while i < cnt do
		byte_array[i]="\0"
		i+=1
	end
	return byte_array.join

end

###############################
#
#	GetPasswordHash
#


def GetPasswordHash(username, password)
	s = PrepareUsernameAndPassword(username, password)
	o = OraEncrypt(s, "\x01\x23\x45\x67\x89\xAB\xCD\xEF")
	k = GetNewKey(o)
	o = OraEncrypt(s, k)

	res = GetNewKey(o)
	res = res.unpack("H*")
	res = res.join
	res = res.upcase

	return res
end



##################################################################
#
#  main
#
##################################################################

##################################################################
# Parse input files

query_file, scan_file = ARGV
@sf = File.open(scan_file) { |f1| Nokogiri::XML(f1) }
@qf = File.open(query_file) { |f2| Nokogiri::XML(f2) }
host = @sf.css("host").first.content
port = @sf.css("port").first.content
sid = @sf.css("sid").first.content
username = @sf.css("username").first.content
password = @sf.css("password").first.content

##################################################################
# Start the XML output

StartOutput(host, port, sid, username)

##################################################################
# Connect to the database server

conn = Connect(host, port, sid, username, password)
if conn == 0 then 
	exit
end


##################################################################
# Start the checks

checks = @qf.css("check")
i = 0
while i < checks.length do
	query = checks[i].css("count_check").first.content
	ExecuteCheck(conn, query, checks, i);
	i = i + 1
end


#################################################################
# Do password checks

print "<finding><check>10.0:5:"
DoPwdCheck(conn, "SELECT NAME||','||PASSWORD||':'||PTIME FROM SYS.USER$ WHERE TYPE#=1 AND ASTATUS IN (0, 1)","OPEN");
if $broken == 0 
	puts "0</check>"
else
	$broken = 0
end
puts "</finding>"
print "<finding><check>10.1:2:"
DoPwdCheck(conn, "SELECT NAME||','||PASSWORD||':'||PTIME FROM SYS.USER$ WHERE TYPE#=1 AND ASTATUS NOT IN (0, 1)","LOCKED");
if $broken == 0
	puts "0</check>"
end
puts "</finding>"

##################################################################
# Close the XML output

EndOutput()





#####################################################################
#
# You have reached your destination
#
#####################################################################