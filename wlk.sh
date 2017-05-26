#!/bin/bash
# Name: Wrong Listener Killer
# Description: Makes sure that the wrong apps don't listen to the ports you want
# Help: Default settings are to make sure that what listens to port :80 is httpd and started as root
# Developer: Robin Labadie
# Version: 2017-05-24

## Settings
portcheck=":80" # Which port to check
allowedname="httpd" # Which process should we get on speccified port
allowedpath="/usr/sbin/httpd" # Which is the correct path to run it
allowedusers="root;" # Which is the correct user to run it (separate with ; )

logdir="/root" # Log directory (don't end with /)
maillog="root@localhost" # Mail to send an alert to if a threat is detected

## Misc vars
selfname="wlk" # Name of the script and log
log="${logdir}/${selfname}.log" # Define log name
maillogsize="10" # Define the amount of log to send by mail

############
### Code ###
############

## Logging
# Create logfile
if [ -n "${log}" ]&&[ ! -f "${log}" ]; then
	touch "${log}"
fi

# Simple echo with date and selfname
# Usage fn_echo "Your Message"
fn_echo(){
	currmessage="$@"
	echo -e "$(date +%Y-%m-%d_%H:%M:%S) - ${selfname} - ${currmessage}"
}

# Echo with date and output to log at the same time
# Usage fn_logecho "Your Message"
fn_logecho(){
	currmessage="$@"
	echo -e "$(date +%Y-%m-%d_%H:%M:%S) - ${selfname} - ${currmessage}"
	echo -e "$(date +%Y-%m-%d_%H:%M:%S) - ${selfname} - ${currmessage}" >> "${log}"
}

# Set different vars
fn_set_vars(){
	pid="$(netstat -atunp | grep "${portcheck} " | grep LISTEN | awk '{print $7}' | awk -F "/" '{print $1}')"
	# Is something listening to the given port
	if [ -z "${pid}" ]; then
		fn_logecho "[ERROR] Nothing found on port ${portcheck}"
		fn_logecho "Exiting"
		exit 1
	else
		# Check name of the process listening to port 80
		pidname="$(netstat -atunp | grep "${portcheck} " | grep LISTEN | awk '{print $7}' | awk -F "/" '{print $2}')"
		# Find out which user owns this PID
		piduser="$(ps -u -p "${pid}" | tail -1 | awk '{print $1}')"
		# Find out the start command (location) of the PID
		pidcommand="$(ps -u -p "${pid}" | tail -1 | awk '{print $11}')"
		# If one of these vars are unset, then something went wrong
		if [ -z "${pidname}" ]||[ -z "${piduser}" ]||[ -z "${pidcommand}" ]; then
			fn_logecho "[ERROR] Could not get app info with PID"
			fn_logecho "Exiting"
			exit 1
		fi
		# Display some nice output to the user
		fn_echo "Current program listening to ${portcheck} is : PID: ${pid}\tName: ${pidname}\tUser: ${piduser}\tPath: ${pidcommand}"
	fi
}

fn_define_vars(){
	pid="$(netstat -atunp | grep "${portcheck} " | grep LISTEN | awk '{print $7}' | awk -F "/" '{print $1}')"
	pidname="$(netstat -atunp | grep "${portcheck} " | grep LISTEN | awk '{print $7}' | awk -F "/" '{print $2}')"
	piduser="$(ps -u -p "${pid}" | tail -1 | awk '{print $1}')"
	pidcommand="$(ps -u -p "${pid}" | tail -1 | awk '{print $11}')"
}

## Evaluate issues & take action
fn_killer(){
	# Check if a malicious program is started
	# 1) If the process name listening to port is wrong
	if [ "${pidname}" != "${allowedname}" ]; then
		harm="1"	
		fn_logecho "[WARNING] Program listening to ${portcheck} is ${pidname} instead of ${allowedname}"
	fi

	# 2) If the process doesn't belong to an allowed user
	usersamount="$(echo "${allowedusers}" | awk -F ';' '{ print NF }')"

	# Recursively check if user is part of allowed users
	allowedtorun="0"
	for ((usersindex=1; usersindex <= usersamount; usersindex++)); do
		# Put current user into a test variable
		usertest="$(echo "${allowedusers}" | awk -F ';' -v x=${usersindex} '{ print $x }')"
		# Test if user is allowed, register success if so
		if [ "${piduser}" == "${usertest}" ]; then
			allowedtorun="1"
		fi
	done
	# User not allowed
	if [ "${allowedtorun}" == "0" ]; then
		harm="1"
		fn_logecho "[WARNING] ${piduser} is not allowed to run ${allowedname}"
	fi

	# 3) If the process path isn't right
	if [ "${pidcommand}" != "${allowedpath}" ]; then
		harm="1"
		fn_logecho "[WARNING] ${pidcommand} is not a valid path for ${allowedname}"
	fi

	## Take action
	if [ "${harm}" == "1" ]; then
		fn_logecho "[ALERT] wrong process listening on port ${portcheck} found"
		fn_logecho "[INFO] The following process will be killed: ${pid} ${pidname} ${piduser} ${pidcommand}"
		kill -9 "${pid}"
		fn_echo "[INFO] Sending mail alert"
		tail -${maillogsize} "${log}" | mail -s "$(hostname -s) - ${pidname} - ${portcheck} killed" ${maillog}
	else 
		fn_logecho "[OK] This program seems legit, exiting."
	fi
}
