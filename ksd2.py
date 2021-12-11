import requests

import json
from akamai.edgegrid import EdgeGridAuth
#Enter SwitchKey below
skey=""
#Enter API creds
baseurl = ''
s = requests.Session()
s.auth = EdgeGridAuth(
client_secret = '',
access_token = '',
client_token = ''
)
# PULL CONFIGURATIONS
config=s.get(baseurl + ("/appsec/v1/configs?accountSwitchKey="+skey) , headers = {'PAPI-Use-Prefixes': 'true'})
configs = json.loads(config.text)

configlist = (configs['configurations'])

for gdictionary in configlist:
	for key,value in gdictionary.items():
		configid= str(gdictionary['id'])
		configname=str(gdictionary['name'])
		try:
			prod=str(gdictionary['productionVersion'])
		except(KeyError):
			key="bypass"	
		try:
			stage=str(gdictionary['stagingVersion'])
		except(KeyError):
			key="bypass"
		
		latest=str(gdictionary['latestVersion'])
		
		
	print("\n Config Name: "+configname)
	if latest != "None":
		prodversion=latest
	if stage != "None":
		prodversion=stage
	if prod != "None":
		prodversion=prod
	policy=s.get(baseurl + ("/appsec/v1/configs/"+configid+"/versions/"+prodversion+"/security-policies?accountSwitchKey="+skey) , headers = {'PAPI-Use-Prefixes': 'true'})
	pol=json.loads(policy.text)
	plist = (pol['policies'])
	for pdictionary in plist:
		for key,value in pdictionary.items():
			pid= str(pdictionary['policyId'])
			policyname= str(pdictionary['policyName'])
		mode =s.get(baseurl + ("/appsec/v1/configs/"+configid+"/versions/"+prodversion+"/security-policies/"+pid+"/mode?accountSwitchKey="+skey) , headers = {'PAPI-Use-Prefixes': 'true'})
		modes=json.loads(mode.text)
		mod =(modes['mode'])
		try:
			ksdversion=(modes['current'])
		except(KeyError):
			key="bypass"
		
		if mod =="AAG":
			ag=s.get(baseurl + ("/appsec/v1/configs/"+configid+"/versions/"+prodversion+"/security-policies/"+pid+"/attack-groups?accountSwitchKey="+skey) , headers = {'PAPI-Use-Prefixes': 'true'})
			ags=json.loads(ag.text)
			aglist = (ags['attackGroupActions'])
			for agdictionary in aglist:
				for key,value in agdictionary.items():
					group=str(agdictionary['group'])
					action=str(agdictionary['action'])
				if group == "CMDI":
					print(" Policy Name:"+policyname+" , WAF Mode:"+mod+" , Command Injection Mode: "+ action)
		
		if mod == "KRS":
			kr=s.get(baseurl + ("/appsec/v1/configs/"+configid+"/versions/"+prodversion+"/security-policies/"+pid+"/rules?accountSwitchKey="+skey) , headers = {'PAPI-Use-Prefixes': 'true'})

			krs=json.loads(kr.text)
		
			klist = (krs['ruleActions'])
			
			for kdictionary in klist:
				for key,value in kdictionary.items():
					ids=str(kdictionary['id'])
					action=str(kdictionary['action'])
				if ids == "3000014":
					test=action
			ag=s.get(baseurl + ("/appsec/v1/configs/"+configid+"/versions/"+prodversion+"/security-policies/"+pid+"/attack-groups?accountSwitchKey="+skey) , headers = {'PAPI-Use-Prefixes': 'true'})
			ags=json.loads(ag.text)
			aglist = (ags['attackGroupActions'])
			for agdictionary in aglist:
				for key,value in agdictionary.items():
					group1=str(agdictionary['group'])
					action1=str(agdictionary['action'])
				if group1 == "CMD":
					print(" Policy Name:"+policyname+" , WAF Mode:"+mod+" , KRS rule 3000014 set to "+test+" mode, Attack Group is in "+action1+" mode. KRS Ruleset Version:"+ksdversion)
