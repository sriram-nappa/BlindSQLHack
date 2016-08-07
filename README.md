# BlindSQLHack
  Blind SQL Injection is a type of SQL injection where the attacker is not aware of the error messages and can only guess the information based on the status of the webpage. The most common way is to use a binary search to guess the information but this approach is time consuming, another way is to trick the server to through an exception on malformed requests and try to extract data from the exception. This is the core concept used in this tool.
# Getting Started
## Prerequisites
  This tool is built using python and requires the language to run it.
  
  a. Install python
  ```
  sudo apt-get install python
  ```
  b. Install python package manager
  ```
  sudo easy_install pip
  ```
  c. Install required packages
  ```
  sudo pip install requests
  sudo pip install prettytable
  ```
# Deployment
a. Download the file daredevil.py or create a new file and copy the contents of daredevil.py to it and save it.
b. If you saved it as a python file then run it using the following command
  ```
  python daredevil.py
  ```
  or
  If you want to convert it to a executable file and run it, use the following commands,
  ```
  chmod a+x daredevil.py
  mv daredevil.py daredevil
  ./daredevil
  ```
## Example
  ```
  $./daredevil
  Enter website with absolute url:
  http://www.everyway-medical.com/products.php?id=2
  ```
  Let the program run its course till it presents you with options.

## Tested URLs
  http://www.everyway-medical.com/products.php?id=2
  
  http://testphp.vulnweb.com/listproducts.php?cat=2
  
# Authors
* **Mohamed Abdul Huq Ismail**
* **Sriram Poondi Chinappa**
