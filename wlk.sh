#!/bin/bash
# Name: Wrong Listener Killer
# Description: Makes sure that the wrong apps don't listen to the ports you want
# Help: Default settings are to make sure that what listens to port :80 is httpd and started as root
# Developer: Robin Labadie
# Website: www.lrob.fr
# Version: 2017-05-24

## Settings
portcheck=":80" # Which port to check
allowedname="httpd" # Which process should we get on speccified port
allowedpath="/usr/sbin/httpd" # Which is the correct path to run it
allowedusers="root;" # Which is the correct user to run it (separate with ; )

logdir="/root" # Log directory (don't end with /)
mailalert="yes" # Wether to send a mail alert or not (yes/no)
mailaddress="root@localhost" # Mail to send an alert to if a threat is detected

maxruns="30" # How many PID this script can kill

## Misc vars
selfname="wrong_listener_killer" # Name of the script and log
log="${logdir}/${selfname}.log" # Define log name

############
### Code ###
############


### MISC FUNCTIONS ###
# Manage logs
fn_logging(){
	# Create logfile
	if [ -n "${log}" ]&&[ ! -f "${log}" ]; then
		touch "${log}"
	fi
}

# Simple echo with date and selfname
# Usage fn_echo "Your Message"
fn_echo(){
	currmessage="$@"
	echo -e "$(date +%Y-%m-%d_%H:%M:%S) - ${selfname} - ${currmessage}"
}

# Echo with date and output to log at the same time
# Usage fn_logecho "Your Message"
fn_logecho(){
	fn_echo
	echo -e "$(date +%Y-%m-%d_%H:%M:%S) - ${selfname} - ${currmessage}" >> "${log}"
	currlog="${currlog}$(echo -e "$(date +%Y-%m-%d_%H:%M:%S) - ${selfname} - ${currmessage}")"
}

# Send mail alert
fn_mail_alert(){
	if [ "${mailalert}" == "yes" ]; then
		fn_logecho "[INFO] Sending mail alert to: ${mailaddress}"
		echo "${currlog}" | mail -s "$(hostname -s) - ${pidname} - ${portcheck} killed" ${mailaddress}
	fi
	# Since this is the last action that should occur
	exit
}

### CORE FUNCTIONS ###

# Check if we can find the PID of a listening program on $portcheck
fn_define_pid(){
	pid="$(netstat -atunp | grep "${portcheck} " | grep LISTEN | awk '{print $7}' | awk -F "/" '{print $1}')"
	# If nothing listens unpon first start
	if [ -z "${pid}" ]&&[ -z "${actiontaken}" ]; then
		fn_logecho "[INFO] Nothing found on port ${portcheck} | Exit"
		exit
	# If nothing listens after getting some processes killed
	elif [ -z "${pid}" ]&&[ "${actiontaken}" == "1" ]; then
		fn_logecho "[OK] Nothing listens on port ${portcheck} anymore | Exit"
		# Send mail alert 
		fn_mail_alert
	fi
}

# Define what listens to $portcheck
fn_define_vars(){
	fn_define_pid
	pidname="$(netstat -atunp | grep "${portcheck} " | grep LISTEN | awk '{print $7}' | awk -F "/" '{print $2}')"
	piduser="$(ps -u -p "${pid}" | tail -1 | awk '{print $1}')"
	pidcommand="$(ps -u -p "${pid}" | tail -1 | awk '{print $11}')"
	# If one of these vars are unset, then something went wrong
	if [ -z "${pidname}" ]||[ -z "${piduser}" ]||[ -z "${pidcommand}" ]; then
		fn_logecho "[ERROR] Could not get app info with PID"
		fn_logecho "Exiting"
		exit 1
	fi
	# Provide info to the user
	fn_echo "Current program listening to ${portcheck} is : PID: ${pid}\tName: ${pidname}\tUser: ${piduser}\tPath: ${pidcommand}"
}

## Evaluate issues
fn_evaluate(){
	# Check process name
	if [ "${pidname}" != "${allowedname}" ]; then
		harm="1"
	fi

	# Check process ownership
	# We will be using a loop since multiple users might be allowed to run it
	# See how many users we have to check so that we can end the loop
	usersamount="$(echo "${allowedusers}" | awk -F ';' '{ print NF }')"
	allowedtorun="0" # This var is the test result and will be set to 1 if the right user is detected
	# Entering the loop to go through allowed users
	for ((usersindex=1; usersindex <= usersamount; usersindex++)); do
		# Put current user into a test variable
		usertest="$(echo "${allowedusers}" | awk -F ';' -v x=${usersindex} '{ print $x }')"
		# Test if user is allowed, register success if it is
		if [ "${piduser}" == "${usertest}" ]; then
			allowedtorun="1"
		fi
	done
	# Result
	if [ "${allowedtorun}" == "0" ]; then
		harm="1"
	fi

	# Check process path
	if [ "${pidcommand}" != "${allowedpath}" ]; then
		harm="1"
	fi
}

## Take action
fn_action(){
	## Problematic process was found
	if [ "${harm}" == "1" ]; then
		fn_logecho "[ALERT] Process on port ${portcheck} does not meet requirements"
		fn_logecho "[INFO] Expected: Name: ${allowedname}\tUser: ${allowedusers}\tPath: ${allowedpath}"
		fn_logecho "[INFO] Actual  : Name: ${pidname}\tUser: ${piduser}\tPath: ${pidcommand}"
		fn_logecho "[ACTION] Killing PID ${pid}"
		kill -9 "${pid}"
		# Reset harm for future tests
		unset harm
		# Misc var to tell that an action has been taken
		actiontaken="1"
		# Misc var to count how many time we ran this
		count=$(($z+1))
		# If $count is greater or equel to $maxruns; then end there
		if [ "${count}" -ge "${maxruns}" ]; then
			fn_logecho "[WARNING] Exiting because the loop has reached the maximum ${maxruns} runs"
			fn_mail_alert
		# Otherwise, let's run it again
		else
			fn_run_functions
		fi
	elif [ "${actiontaken}" == "1" ]; then
		fn_logecho "[OK] The process on port ${portcheck} now meets requirements
		exit
	else
		fn_logecho "[OK] The process on port ${portcheck} meets requirements
		exit
	fi
}

### RUN FUNCTIONS ###
fn_logging
fn_run_functions(){
	fn_define_pid
	fn_define_vars
	fn_evaluate
	fn_action
}
