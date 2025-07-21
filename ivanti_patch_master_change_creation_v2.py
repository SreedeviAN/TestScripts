#!/usr/bin/env python

#Stackstorm action Module
from lib.base_action import BaseAction

#API Request Module
import requests
from requests_ntlm import HttpNtlmAuth
from requests.auth import HTTPBasicAuth

#DateTime Module
import pytz
from datetime import datetime, timedelta

#Email Modules
import smtplib
import email.utils
from email.mime.text import MIMEText

#Json Module
import json

#sleep module
from time import sleep

#subprocess module - importing only check_output to get the output of the shell script executed
from subprocess import check_output
import subprocess
import paramiko

#winrm module
import winrm
#xml module
import xml.etree.ElementTree as ET
import re
import os

class IvantiPatchMasterChangeCreationv2(BaseAction):
    def __init__(self, config):
        """Creates a new Action given a StackStorm config object (kwargs works too)
        :param config: StackStorm configuration object for the pack
        :returns: a new Action
        """
        super(IvantiPatchMasterChangeCreationv1, self).__init__(config)

    def run(self, ivanti_server,ivanti_username, ivanti_password, winrm_username, winrm_password, companyname, assignment_group, change_management_group, req_by_email, day_difference):
        
        scan_folder = "C:\\Windows\\System32\\Tasks\\Ivanti\\Security Controls\\Scans"
        start_boundary = ''
        end_boundary = ''
        machine_group_name = ''
        cdata_content = ''
        deploy_id = ''
        auto_deploy = 'NO'
        servervalidate = []
        serverconnectivityfailedformat=''
        serverconnectivityfailed = []
        transferdetails = []
        servernotincmdb = []
        servertransferdetails = {}
        serverstoignore = []
        changescreated = []
        nopatch_servers = []  
        patch_list = ''
        latestPatchScanId = ''
        ivanti_server = ''
        scan_machine_id = ''
        scan_patches = ''
        scan_file_exists = 0        
    
        url = self.config['servicenow']['url']
        self.sn_username = self.config['servicenow']['username']
        self.sn_password = self.config['servicenow']['password']
        headers = { "Content-Type":"application/json" } 
        self.som_company_sys_id =  self.config['servicenow']['company_sys_id']
        
        #Fetch previous Master Change data from CMDB        
        master_change_url = "https://nttdsuat.service-now.com/api/now/table/change_request?sysparm_query=active=true^state!=6^state!=7^state!=8^state!=9^company.sys_id=1c3a70e537fd75000f8327d2b3990e08^priority=3^ORpriority=4^descriptionLIKEPatch%20Scan%20File%20Name^descriptionLIKEMachine%20Group%20Name^short_descriptionLIKEMicrosoft%20Patching%20PROD^enda_dateRELATIVELT@hour@ahead@24^start_dateRELATIVEGT@hour@ago@24&sysparm_fields=number"
        sn_url = "https://{0}{1}".format(url, master_change_url)
        self.servicenow_headers = {'Content-type': 'application/json','Accept': 'application/json'}             
        master_change_result = requests.request('GET', sn_url, auth=(self.sn_username, self.sn_password), headers=self.servicenow_headers, verify=False)             
        master_change_result = master_change_result.json()
        print(master_change_result)

        chg_st2_key = 'servicenow.master_change_requests_processing'
        processing_master_chg_requests = self.st2_client.keys.get_by_name(chg_st2_key)
        print("Processing change requests are: {}".format(processing_master_chg_requests))
        processing_chg_requests = [] if processing_chg_requests is None else ast.literal_eval(processing_master_chg_requests)
        print("Existing change requests are: {}".format(processing_master_chg_requests))
        for chg in sn_change_requests:
            #Skip any change request that are currnetly being processed
            if chg['number'] in processing_chg_requests:
                print('In continue')
                if chg['end_date'] == "":
                    print('End Time is blank')
                    continue
                planned_end_date = chg['end_date']
                datesplit = planned_end_date.split('-')
                year1 = datesplit[0]
                month1 = datesplit[1]
                day1 = datesplit[2].split(" ")[0]
                hour1 = datesplit[2].split(" ")[1].split(":")[0]
                minute1 = datesplit[2].split(" ")[1].split(":")[1]
                print(year1, month1, day1)
                planned_end_time = datetime(year=int(year1), month=int(month1), day=int(day1), hour=int(hour1), minute=int(minute1))
                print(planned_end_date)
                changekey = chg['number']
                lasttriggertime = str(datetime.now())
                self._logger.info('Processing change request:' + chg['number'])
                processing_chg_requests.append(chg['number'])               
            else:  
                print("In Else: Executing the change request for the first time")
                planned_end_date = chg['end_date']
                datesplit = planned_end_date.split('-')
                year1 = datesplit[0]
                month1 = datesplit[1]
                day1 = datesplit[2].split(" ")[0]
                hour1 = datesplit[2].split(" ")[1].split(":")[0]
                minute1 = datesplit[2].split(" ")[1].split(":")[1]
                planned_end_time = datetime(year=int(year1), month=int(month1), day=int(day1), hour=int(hour1), minute=int(minute1))
                print(planned_end_date)             
                self._logger.info('Processing change request:' + chg['number'])
                processing_chg_requests.append(chg['number'])
                chg_str = str(processing_chg_requests)
                kvp = KeyValuePair(name=chg_st2_key, value=chg_str)
                self.st2_client.keys.update(kvp)
                print("Check description") 

                change_plan = chg['change_plan']
                test_plan = chg['test_plan']
                backout_plan = chg['backout_plan']
                detailed_desc = chg['description']
                planned_start_date = chg['start_date']
                planned_end_date = chg['end_date']
                chg_scanfile_name = detailed_desc.split("Patch Scan File Name: ")[1]
                chg_scanfile_name = chg_scanfile_name.split("Machine Group Name")[0]
                chg_scanfile_name = chg_scanfile_name.strip()
                #print("chg_scnafile_name - ",chg_scanfile_name)
                chg_machine_grp_name = detailed_desc.split("Machine Group Name:")[1]
                chg_machine_grp_name = chg_machine_grp_name.split("----")[0]
                chg_machine_grp_name = chg_machine_grp_name.strip()
                #print("chg_machine_grp_name - ", chg_machine_grp_name)  

                session = winrm.Session(f'https://' + ivanti_server + ':5986/wsman', auth=(ivanti_username,ivanti_password), transport='ntlm',server_cert_validation='ignore')        
                list_scanfiles_cmd = 'Get-ChildItem "C:\\Windows\\System32\\Tasks\Ivanti\\Security Controls\\Scans" -File | % { $_.FullName }'
                list_result =  session.run_ps(list_scanfiles_cmd)
                files = list_result.std_out.decode().splitlines()
                files = [f.strip() for f in files if f.strip()]
        
                for file in files:
                #Read file content
                    file_read_cmd = 'Get-Content -Path "'+ file +'" -Raw'
                    file_read_result =  session.run_ps(file_read_cmd)
                    file_name = str(file.split("Scans\\")[1])
                    print(file_name)
                    xml_content = file_read_result.std_out.decode()
                       
                    if file_name == chg_scanfile_name: 
                        scan_file_exists = 1
                        print("Scan File exists")
                        try:
                            root = ET.fromstring(xml_content)
                            ns = { 't': 'http://schemas.microsoft.com/windows/2004/02/mit/task'}
                            start_boundary_elem = root.find(".//t:StartBoundary",ns)
                            start_boundary = start_boundary_elem.text
                            end_boundary_elem = root.find(".//t:EndBoundary",ns)
                            end_boundary = end_boundary_elem.text
                            machine_group_name_elem = root.find(".//t:Description",ns)
                            machine_group_name = machine_group_name_elem.text
                            action_xml_elem = root.findall(".//t:Data",ns)[1]
                            inner_root = ET.fromstring(action_xml_elem.text)
                            method_node = inner_root.find(".//method")
                            if method_node is not None:
                                arg01 = method_node.attrib.get("arg01","")
                                if "-deployid" in arg01:
                                    auto_deploy = "YES"
                                else:
                                    auto_deploy = "NO"
                                    print("auto deploy value: ",auto_deploy)
                            if start_boundary is not None:
                                print(start_boundary)
                            else:
                                print("No StartBoundary value")
                            if end_boundary is not None:
                                print(end_boundary)
                            else:
                                print("No EndBoundary value")
                            if machine_group_name is not None:
                                print(machine_group_name)
                            else:
                                print("No Machine Group value")
                        except ET.ParseError as e:
                            print("XML Parse Error: {e}")
                    
                        start_boundary = start_boundary.strip()
                            if '.' in start_boundary:
                                start_boundary = start_boundary.split('.')[0]
                    timesplit = start_boundary.split("-")
                    time1 = timesplit[2].split("T")[1].split(":")
                    servernextpatchtime = datetime(int(timesplit[0]),int(timesplit[1]),int(timesplit[2].split("T")[0]),int(time1[0]), int(time1[1]),
                    int(time1[2].split("+")[0]))
                    timediff = servernextpatchtime - (datetime.now())
                    print("timediff: ", timediff)
                    end_boundary = end_boundary.strip()
                    if '.' in end_boundary:
                        end_boundary = end_boundary.split('.')[0]
                    timesplit1 = end_boundary.split("-")
                    time2 = timesplit1[2].split("T")[1].split(":")
                    serverendpatchtime = datetime(int(timesplit1[0]),int(timesplit1[1]),int(timesplit1[2].split("T")[0]),int(time2[0]), int(time2[1]), int(time2[2].split("+")[0]))
                    startdate = str(servernextpatchtime)
                    enddate = str(serverendpatchtime)
                    #print(startdate)
                    #print(enddate)

                    if machine_group_name == chg_machine_grp_name:
                        if startdate == planned_start_date:
                            print(auto_deploy)
                            if auto_deploy == "YES":
                                try:
                                    #Get the Machine Group Id
                                    #apiheader = {'Accept': 'application/json','Content-type': 'application/json'}
                                    ivanti_group_url = "https://" + ivanti_server + ":3121/st/console/api/v1.0/machinegroups?name=" + machine_group_name
                                    ivanti_groups = requests.get(ivanti_group_url, auth=HttpNtlmAuth(ivanti_username,ivanti_password), headers=header, verify=False)
                                    ivanti_groups_json = ivanti_groups.json()
                                    ivanti_group_id = ivanti_groups_json['value'][0]['id']

                                    #Get the Machines in the Machine Group and create Patch Change for each Server
                                    server_data_url = "https://" + ivanti_server + ":3121/st/console/api/v1.0/machinegroups/"+str(ivanti_group_id)+"/discoveryfilters?category=MachineName"
                                    serverdata = requests.get(server_data_url, auth=HttpNtlmAuth(ivanti_username,ivanti_password), headers=apiheader, verify=False)
                                    #print(server_data_url)
                                    serverdatajson = serverdata.json()
                                    servers = ''
                                    # Get the missing patches in Servers
                                    for server in serverdatajson['value']:
                                        if server['category'] == 'MachineName':
                                            servers = servers + "\n" +  server['name']
                                            ivanti_server = server['name']
                                            machine_url = "https://" + ivanti_server + ":3121/st/console/api/v1.0/machine?name=" + ivanti_server
                                            try:
                                                machine_url = "https://" + ivanti_server + ":3121/st/console/api/v1.0/machine?name=" + ivanti_server
                                                machine_data = requests.get(machine_url, auth=HttpNtlmAuth(ivanti_username,ivanti_password), headers=apiheader, verify=False)
                                                machine_data = machine_data.json()
                                                #print(machine_data)
                                                #latestPatchScanId = machine_data['value'][0]['latestPatchScanId']
                                                #print(latestPatchScanId)
                                                #scan_url = "https://" + ivanti_server + ":3121/st/console/api/v1.0/patch/scans/" + latestPatchScanId + "/machines"
                                                #scan_machines = requests.get(scan_url, auth=HttpNtlmAuth(ivanti_username,ivanti_password), headers=apiheader, verify=False)
                                                #scan_machines = scan_machines.json()
                                                #scan_machine_id = scan_machine_data['value'][0]['id']
                                                #scan_patches_url ="https://" + ivanti_server + ":3121/st/console/api/v1.0/patch/scans/" + latestPatchScanId + "/machines/" + scan_machine_id + "/patches"
                                                #scan_patches = requests.get(scan_patches_url,auth=HttpNtlmAuth(ivanti_username,ivanti_password), headers=apiheader, verify=False)
                                                #scan_patches = scan_patches.json()
                                                #for scan_patch in scan_patches:
                                                    #if scan_patch['value'][0]['scanState'] == "MissingPatch":
                                                        #patch_list = patch_list + '\n' + scan_patch['value'][0]['productName']
                                                #print("Patch List:",patch_list)
                                            except Exception as e:
                                            print("An error occured while fetching patch list: "+ str(e))
                                    patch_list = "Microsoft Patches"
                                               
                        if timediff.days == day_difference:
                        servername = ivanti_server
                        #servervalidate.append(ivanti_server)
                        #print("Next Patch window is {} which is {} days away from today".format(servernextpatchtime.astimezone(pytz.timezone('GMT')),day_difference))                            
                        #self.sn_username = self.config['servicenow']['username']
                        #self.sn_password = self.config['servicenow']['password']            
                    shortdescription = companyname + " || Microsoft Patching PROD ||  "  + "|| Winodows"
                    startdate = str(servernextpatchtime)
                    enddate = str(serverendpatchtime)
                    suppression_start = str((servernextpatchtime + timedelta(minutes=1))) 
                    suppression_end = str((serverendpatchtime - timedelta(minutes=1)))
                    #servertransferdetails.update({"servername":ivanti_server, "start_date":startdate, "end_date":enddate, "expected_start":startdate, "shortdescription":shortdescription, "description":shortdescription})
                               
                    ###### adding change creation part ######                               
                    test_plan="""Verify system availability 
Verify successful patch installation
Generate Patch compliance report
Turn over server to POC for application validation"""
                    description = """What is this change for?
This change is the regularly scheduled compliance patching of this server
This change is the  parent change for  Nucleus Patching Automation ("""+ companyname +""" - Windows - PROD Servers). The servers will be unavailable during the restart of the servers.
This change is scheduled during the approved patching window
-------------------------------------------------
Patch Scan File Name: """ + file_name + """
Machine Group Name: """ + machine_group_name + """
--------------------------------------------------
Servers Impacted 
=================== """ + servers + """
\n Patch List
=================== \n """ + patch_list
                    backout_plan = """In the event that a system or application becomes unavailable, the offending patch will be uninstalled.
If uninstalling the patch does not restore services, the server will be restored from backup following documented DR plans."""
                    work_notes = 'This Master Patch change is created by Automation'
                    change_plan = "This Master Patch change is created by Automation"
                    payload = {
                        'start_date': startdate,
                        'state': 1,
                        'assigned_to': self.sn_username,
                        'assignment_group': assignment_group,
                        'backout_plan': backout_plan,
                        'category': 'Perform',
                        'change_plan': change_plan,
                        'cmdb_ci': ivanti_server,
                        'company': companyname,
                        'contact_type': 'email',
                        'end_date': enddate,
                        'expected_start': startdate,
                        'implementation_plan': 'Test',
                        'justification': 'justification',
                        'risk': 4,
                        'test_plan': test_plan,
                        'type': "Normal",
                        'u_change_management_group': change_management_group,
                        'work_notes': work_notes,
                        'short_description': shortdescription,
                        'description': description,
                        'approval': 'approved',
                        'u_req_by_email': req_by_email,
                        'impact': 3,
                        'u_change_environment': 'Production',
                        'u_subcategory': 'Restart Scheduled Maintenance',
                        'u_is_incident_suppression_requ': 'true',
                        'u_change_reason': 'Maintenance',
                        'u_suppression_start': suppression_start,
                        'u_suppression_end': suppression_end,
                        'u_validation_time': '00:20:00',
                        'u_backout_time': '00:10:00',
                        'u_implementation_time': '0:30:00',
                        'u_total_change_time': '01:00:00',
                        'location': 'Location Not Provided',
                        'u_locations': 'Location Not Provided',
                        'u_approvers': 'Integration Approver',
                        'requested_by': self.sn_username
                    }
                    #endpoint =  '/api/now/table/change_request'
                    endpoint = '/api/ntt11/changestackstormautomation/create_change'
                    #url = "nttdsuat.service-now.com"
                    url = self.config['servicenow']['url']
                    self.sn_username = self.config['servicenow']['username']
                    self.sn_password = self.config['servicenow']['password']
                    sn_url = "https://{0}{1}".format(url, endpoint)
                    headers = {'Content-type': 'application/json','Accept': 'application/json'}
                    method= 'POST'
                    createdchangenumber = ''
                    change = requests.request("POST",sn_url, auth=HTTPBasicAuth(self.sn_username, self.sn_password), json=payload, headers=headers, verify=False)  
                    #change = self.sn_api_call('POST', endpoint, payload=payload)
                    change = change.json()
                    #print(change)
                    #change = self.sn_api_call('POST', endpoint, payload=payload)
                    createdchangemessage = change['result']['message']
                    #print(createdchangemessage)
                    createdchangenumber = createdchangemessage.split(':')[1].strip().split(' ')[0].strip()
                    #print(createdchangemessage)
                    #createdchangenumber = change["number"]["value"]
                    #createdchangeid = change["sys_id"]["value"]
                    print("Change Created: " ,createdchangenumber)
                                    
                    update_endpoint = '/api/ntt11/v1/chg_mgmt/UpdateChange'
                    payload = {
                        "number": createdchangenumber,
                        "company": companyname,
                        "u_change_management_group": change_management_group
                    }
                    response = self.sn_api_call('POST', update_endpoint, payload=payload)
                    #update_endpoint = "https://{0}{1}".format(url, update_endpoint)
                    #response = requests.request("POST",update_endpoint, auth=HTTPBasicAuth(self.sn_username, self.sn_password), json=payload, headers=headers, verify=False)
                    sleep(2)
                                    
                    # First step of change approval Request
                    endpoint1 = '/api/dems/ebonding_change_automation/changeAutomation'
                    payload1 = {"company":companyname,"number":createdchangenumber,"request_approval":"Yes"}
                    change1 = self.sn_api_call('POST', endpoint1, payload=payload1)
                    sleep(10)
                                    
                    # Second Step of change approval
                    endpoint2 = '/api/dems/ebonding_change_automation/changeAutomation'
                    payload2 = {"company":companyname,"number":createdchangenumber,"approval":"Approve"}
                    change2 = self.sn_api_call('POST', endpoint2, payload=payload2)
                    sleep(10)
 
                    # Next step of change approval Request
                    endpoint3 = '/api/dems/ebonding_change_automation/changeAutomation'
                    payload3 = {"company":companyname,"number":createdchangenumber,"request_approval":"Yes"}
                    change3 = self.sn_api_call('POST', endpoint3, payload=payload3)
                    sleep(10)

                    # Next Step of change approval
                    endpoint4 = '/api/dems/ebonding_change_automation/changeAutomation'
                    payload4 = {"company":companyname,"number":createdchangenumber,"approval":"Approve"}
                    change4 = self.sn_api_call('POST', endpoint4, payload=payload4)
                    sleep(10)
                                    
                    # Next Step of change approval    
                    endpoint5 = '/api/dems/ebonding_change_automation/changeAutomation'
                    payload5 = {"company":companyname,"number":createdchangenumber,"approval":"Approve"}
                    change5 = self.sn_api_call('POST', endpoint5, payload=payload5)

                    changenumberandserver = createdchangenumber + " : " + servername
                    #print(changenumberandserver)
                    changescreated.append(changenumberandserver)
                    print("changescreated value",changescreated)
                    print(servertransferdetails)
                    ######## end of change creation ##########

                        else:
                            print("Schedule Time is changed")
                            reschedule_endpoint = '/api/ntt11/changestackstormautomation/update_change'
                            sn_url = "https://{0}{1}".format(url,reschedule_endpoint)
                            headers = {'Content-type': 'application/json','Accept': 'application/json'}
                            #Update Change
                            endpoint = '/api/now/table/change_request/'+ change_sys_id
                            payload = {
                                'number': change_id,
                                'company': companyname,
                                'work_notes': 'Rescheduling the Change as per the updated Scan file',
                                'start_date': startdate,
                                'end_date': enddate,
                                'expected_start': startdate,
                                'u_validation_time': '00:20:00',
                                'u_backout_time': '00:10:00',
                                'u_implementation_time': '00:30:00',
                                'u_total_change_time': '01:00:00'
                            }
                            response1 = requests.request('POST',sn_url, auth=HTTPBasicAuth(self.sn_username, self.sn_password), json=payload, headers=headers, verify=False)
                            print(response1.json())
   
                if scan_file_exists == 0:
                    print("No Scanfile Found.Cancelling the Change - ",change_id)
                    #endpoint = '/api/now/table/change_request/' + change_sys_id
                    endpoint = '/api/ntt11/changestackstormautomation/cancel_change'
                    sn_url = "https://{0}{1}".format(url, endpoint)
                    payload = {
                        'number': change_id,
                        'state': '9',
                        'company': companyname,
                        'u_cancel_reason': 'No Longer Required',
                    }
                    cancel_change_request = requests.request("POST",sn_url, auth=HTTPBasicAuth(self.sn_username, self.sn_password), json=payload, headers=headers, verify=False)
                    print(cancel_change_request.json())
