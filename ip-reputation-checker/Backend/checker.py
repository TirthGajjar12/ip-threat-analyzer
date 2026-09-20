import re #this is means regular expression to extreact ips from the input buy giving it a pattern 

def extreact_ips(value):
    pattern = r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"
    matches = re.findall(pattern,value)
    unique_ips = list(dict.fromkeys(matches))
    return unique_ips

r = input("Enter valid ip address:  ") #testing the code for now 
print(extreact_ips(r))
