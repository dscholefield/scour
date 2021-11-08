# scour
Find complex patterns in text log files

	scour version 1.0 - D Scholefield 2005, 2006, 2007

	usage: scour [options] file:[!]<log file> pattern:<pattern>

	[-list] 		list lines from log file that match constraints
	[-nocase]		ignore care in pattern (default is to regard case)
	[-count] 		show count of number of lines in log file that match constraints
	[-yesno]		show either '0' or '1' depending on whether any lines were found
	[-within:<time>]	look for matches within any 'time' period
	[previous:<time>] 	only consider lines in log file added in previous <time> (see below)
	[num:<num>]		look for at least 'num' number of lines (used with -yesno option) 
	[from:<date>] 		bound search to those lines added on or after date (see below)
	[to:<date>]		bound search to those lines added on or before date (see below)
	[-verbose]		be verbose with reporting
	[execute:command]	execute given shell command if scour is successful

	if a '!' is placed before the filename then it is treated as
		a shell command, and the test carried out against the results

	<time> is defined in format 'hh:mm:ss' with or without quotes
	<date> is in Unix date string format 'YYYY-MM-DD HH:MM::SS'
	<pattern> is any Perl regular expression

	list, count, and yesno options are mutually exclusive
	'previous' is mutually exclusive to 'from' and 'to' options

	examples:
	1) look for entries in log file with 'Authentication failure' that have been added in 
	the last hour, and list the lines found

	scour -list previous:'01:00:00' pattern:'Authentication failure' file:'/var/log/system.log'

	2) look for shutdown entries that have occurred between two dates and return
	a '0' or '1' if there have been more than three occasions

	scour -yesno from:'2005-11-11 00:00:00' to:'2005-11-15 23:59:59' num:4 
		pattern:'shutdown: halt' file:'/var/log/system.log'
	
	3) Look for at least three 'Failed su' messages within any 30 minute period
	within the last 24 hours and if found list the matching lines to the terminal
	and execute the command 'mail_alarm'

	scour -list within:00:30:30 pattern:'Failed su' file:'/var/log/auth.log' num:3 
		 -nocase previous:24:00:00 execute:'/usr/local/mail_alarm -s "su failed"' 
