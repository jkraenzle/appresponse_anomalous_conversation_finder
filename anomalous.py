import getpass
import argparse
import urllib3
urllib3.disable_warnings (urllib3.exceptions.InsecureRequestWarning)

# SteelScript
import os
os.environ['AR11_ADVANCED_FEATURES']="True"

from steelscript.appresponse.core.appresponse import AppResponse
from steelscript.common import UserAuth
from steelscript.appresponse.core.reports import DataDef, Report
from steelscript.appresponse.core.types import Key, Value, TrafficFilter
from steelscript.appresponse.core.reports import SourceProxy
from steelscript.appresponse.core.types import TimeFilter

ANOMALOUS_SOURCENAME_DEFAULT = 'aggregates'
ANOMALOUS_LOSSTHRESHOLD_DEFAULT = 20

def authenticate (host, username, password):
	ar = AppResponse (host, auth=UserAuth (username, password))
	return ar

# Record format is [<ar>, "hostname", # of packets, # of bytes]

def report_header_print ():

	print ("%s\t%16s\t%16s\t%10s\t%10s\t%9s\t%9s\t%12s\t%12s\t%36s" % 
		("Index", 
		"Client IP Address", 
		"Server IP Address", 
		"Pkts Out", 
		"Pkts In", 
		"Loss Out", 
		"Loss In", 
		"Bytes In", 
		"Bytes Out", 
		"Summary"))

	return

def report_record_print (index, record, message):
        print ("%d\t%16s\t%16s\t%10s\t%10s\t\t%.2f\t\t%.2f\t%12s\t%12s\t%36s" % 
		(index, 
		record[0], #'cli_tcp.ip' 
		record[1], #'srv_tcp.ip' 
		record[2], #'sum_tcp.payload_packets_c2s'
		record[3], #'sum_tcp.payload_packets_s2c'
		float(record[4]), #'avg_tcp.retrans_ratio_c2s'
		float(record[5]), #'avg_tcp.retrans_ratio_s2c'
		record[6], #'sum_tcp.payload_c2s_bytes'
		record[7], #'sym_tcp.payload_s2c_bytes'
		message))
        return

def report_columns_create (source_name):

	if source_name == 'aggregates':
		columns = [Key('cli_tcp.ip'), Key('srv_tcp.ip'), \
			Value('sum_tcp.payload_packets_c2s'), Value('sum_tcp.payload_packets_s2c'), \
			Value('avg_tcp.retrans_ratio_c2s'), Value('avg_tcp.retrans_ratio_s2c'), \
			Value('sum_tcp.payload_c2s_bytes'), Value('sum_tcp.payload_s2c_bytes')]

	return columns

def report_record_is_anomalous (record, loss_threshold):
	unidirectional = False
	exceeds_loss_threshold = False
	
	in_packets = int(record[2]) #'sum_traffic.packets_m2p'
	out_packets = int(record[3]) #'sum_traffic.packets_p2m'
	
	if (in_packets == 0 and out_packets > 0) or (in_packets > 0 and out_packets == 0):
		unidirectional = True
	
	if record[4] != '#N/D':
		in_loss = int(record[4]) #'avg_tcp.retrans_ratio_c2s'
	else:
		in_loss = 0
	if record[5] != '#N/D':
		out_loss = int(record[5]) #'avg_tcp.retrans_ratio_s2c'
	else:
		out_loss = 0

	if in_loss > loss_threshold or out_loss > loss_threshold:
		exceeds_loss_threshold = True

	if unidirectional and exceeds_loss_threshold:
		return True, "Uni-directional and high packet loss"
	elif unidirectional:
		return True, "Uni-directional"
	elif exceeds_loss_threshold:
		return True, "High packet loss"
	else:
		return False, ""

def report_filter_str_create (source_name, filter):
	
	return ""

def find_anomalous_conversations (source_name, ar, columns, filter_str, top, timerange):
	# Report
	source = SourceProxy (name=source_name)

	if source_name == 'aggregates':
		topbycolumns = [Value('sum_tcp.payload_c2s_bytes'), Value('sum_tcp.payload_s2c_bytes')]

	data_def = DataDef (source=source, columns=columns, granularity=60, resolution=60, time_range=timerange, limit=top, topbycolumns=topbycolumns)
	if filter_str != "" and filter_str != None:
		data_def.add_filter (TrafficFilter (filter_str))

	report = Report (ar)
	report.add (data_def)
	report.run ()

	data = report.get_data ()
	headers = report.get_legend ()

	report.delete ()

	return data

def capture_job_list (ar):

	# Show capture jobs
	headers = ['id', 'name', 'filter', 'state', 'start_time', 'end_time', 'size']
	data = []
	for job in ar.capture.get_jobs():
	    data.append({"id":job.id, "name":job.name,
			"filter": getattr(job.data.config, 'filter', None),
			"state": job.data.state.status.state,
			"start_time": job.data.state.status.packet_start_time,
			"end_time": job.data.state.status.packet_end_time,
			"size": job.data.state.status.capture_size})

	return data

def export_filter_create (search_type, search_objects):
	if (search_type == SEARCH_TYPE_IPADDRESS):
		export_filters = [{"id":"f1", "type":"STEELFILTER", "value":"ip.addr==" + search_objects [0]}]
	else:
		export_filters = [{"id":"f2", "type":"STEELFILTER", "value":"ip.addr==" + search_objects [0] + \
			 " and ip.addr==" + search_objects [1]}]

	return export_filters

def export (ar, job_name, filters, timerange = None, filename = None):

	source = ar.capture.get_job_by_name (job_name)
	if (filename == None):
		filename = job_name + "_export.pcap"

	timefilter = TimeFilter (time_range = timerange)

	with ar.create_export (source, timefilter, filters) as e:
		print ("Downloading to file {}".format (filename))
		e.download (filename, overwrite=True)
		print ("Finished downloading to file {}".format (filename))

	return

def main ():

	parser = argparse.ArgumentParser (description="SteelScript utility to search and download packets in AppResponse")
	parser.add_argument('--hostname', help="Hostname or IP address of the AppResponse 11 appliance")
	parser.add_argument('--username', help="Username for the appliance")
	parser.add_argument('--password', help="Password")
	parser.add_argument('--source_name', help="Source of data")
	parser.add_argument('--top', help="Limit of number of conversations to search")
	parser.add_argument('--loss_threshold', help="Threshold at which to list conversation as anomalous")
	parser.add_argument('--filter', help="Filter to use")
	parser.add_argument('--timerange', help="Time range to analyze (defaults to 'last 1 hour'). Valid formats are "
				"'03/05/20 12:00:00 to 03/06/20 19:53:00'"
				"or '17:09:00 to 18:09:00'"
				"or 'last 14 minutes'")
	parser.add_argument('--filename', help="Filename for packet capture export")
	args = parser.parse_args()

	# Check inputs for required data and prep variables
	if args.hostname == None or args.hostname == "":
		print ("Please specify a hostname using --hostname")
		return
	else:
		hostname = args.hostname

	if args.username == None or args.username == "":
		print ("Please specify a username using --username : ")
		return
	else:
		username = args.username

	if (args.timerange == None or args.timerange == ""):
		print ("Please specify a time range")
		return
	else:
		timerange = args.timerange

	# Check and get the password last of the required attributes because it requires user entry
	# It's best to avoid user entering information and to just return because other information is missing
	if args.password == None or args.password == "":
		print ("Please provide password for account %s" % args.username)
		password = getpass.getpass ()
	else:
		password = args.password

	# Check optional parameters and set defaults
	if args.source_name == None or args.source_name == "":
		source_name = ANOMALOUS_SOURCENAME_DEFAULT
	else:
		source_name = args.source_name

	if args.top == None or args.top == "":
		top = ANOMALOUS_TOP_DEFAULT
	else:
		top = int(args.top)

	if args.loss_threshold == None or args.loss_threshold == "":
		loss_threshold = ANOMALOUS_LOSSTHRESHOLD_DEFAULT
	else:
		loss_threshold = int(args.loss_threshold)

	if args.filter == None or args.filter == "":
		filter = ""
	else:
		filter = args.filter

	columns = report_columns_create (source_name) 
	filter_str = report_filter_str_create (source_name, filter)

	try:
		# Authenticate
		ar = authenticate (hostname, args.username, password)
	except:
		print ("Login failed for %s" % hostname)
		return

	report_data = find_anomalous_conversations (source_name, ar, columns, filter, top, timerange)

	# Display the appliances that have the traffic
	if (len (report_data) > 0):

		i = 1
		header = False
		for record in report_data:
			status, message = report_record_is_anomalous(record, loss_threshold)
			if status == True:
				if header == False:
					report_header_print ()
					header = True
				report_record_print (i, record, message)
				i+=1

		if i > 1:
			print ("Enter the conversation number from which to download packets and hit return > ", end="")
			conv_no = input ()
		else:
			print("No anomalous conversations were found!")
			return
	else:
		print ("The search returned no IP conversations.")
		return

	try:
		# Get Capture Jobs from appliance
		capture_jobs = capture_job_list (ar)
	except:
		print ("The Capture Jobs for the selected appliance could not be retrieved.")
	
	if len(capture_jobs) > 0:
		# Ask the user which Capture Job should be used
		job_no = 1
		for job in capture_jobs:
			print ("%d:\t%s\t%s" % (job_no, job ["name"], job ["state"]))
			job_no += 1

		print ("Enter the Capture Job number from which to download packets and hit return > ", end='')
		job_no = input ()
		job_name = capture_jobs [int (job_no) - 1]["name"]

		export_filters = export_filter_create (report_data[conv_no])
		export (ar, job_name, export_filters, timerange, filename=args.filename)

	return
 
if __name__ == "__main__":
	main ()
