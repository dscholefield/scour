#!/usr/bin/perl

# scour is able to detect lines in any text file that match
# given Perl regular expressions. It can count matches over
# the entire file, and trigger a positive or negative response
# depending on whether the number of matches exceeds the count.
# Various levels of reporting are available: ranging from a
# simple Boolean response, through to dumping the matching
# lines to STDOUT or executing an arbitrary command if conditions
# are met.

# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

=head1  NAME

scour - scour log files for patterns

=head1  SYNOPSIS

B<scour>
[ [ B<-list> ]
|
[ B<-count> ] 
|
[ B<-yesno> ] ]
[ B<-nocase> ]
[ B<-verbose> ]
[ B<-help> ]
[ B<num:> I<number> ] 
[ B<within:> I<time> ] 
[ [ B<previous:> I<time> ]
|
[[ B<from:> I<time> ] 
[ B<to:> I<time> ]] ]
[ B<file:> I<filename> ] 
[ B<pattern:> I<regex> ]
[ B<execute:> I<command> ]


=head1  DESCRIPTION

B<Scour> is a command line script that is
able to detect lines in any text file that match
given Perl regular expressions. It can count matches over
the entire file, and trigger a positive or negative response
depending on whether the number of matches exceeds the count.
Various levels of reporting are available: ranging from a
simple Boolean response, through to dumping the matching
lines to STDOUT, or executing a given command.

The B<scour> can also be limited to specific time periods and
can thus be used as a periodic log watching process by incorporating
it into a cron job.

=head1 COMMAND LINE OPTIONS

=over 4

=item B<-list>

List lines from log file to STDOUT that match constraints (whether or not number of
lines matched is at least that defined by B<num:> option).

=item B<-nocase>		

Ignore care in pattern (default is to regard case).

=item B<-count>

Show count of number of lines in log file that match constraints on STDOUT.

=item B<-yesno>

Show either '0' or '1' on STDOUT depending on whether all constraints were met.

=item B<-verbose>

Produce very verbose output (helpful with testing B<scour> parameters).

=item B<-help>

Print B<scour> help message to STDOUT.

=item B<within:> I<time>
Only check for matches within any period of 'time' or less. Time is specified in
hours minutes and seconds in the form hours:minutes:seconds.

=item B<previous:> I<time>

Only check the log file from 'time' ago to the current time. Time is specified in
hours minutes and seconds in the form hours:minutes:seconds. B<previous:> option is
mutually exclusive to the B<to:> and B<from:> options.

=item B<from:> I<time> and B<to:> I<time> 

Only check the log file lines that have timestamps between the 'from' and 'to'
times. Time is specified in hours minutes and seconds in the form hours:minutes:seconds.
B<from:> and B<to:> options are mutually exclusive to the B<previous:> option.

=item B<file:> I<[!]filename>

The name of the file to perform the B<scour> against. B<scour> understands the timestamps
that are found in standard *nix syslog style text files, as well as Apache web server timestamps. If the 'pling' option is used (!) then the filename can be any shell command, and the output
from STDOUT will be captured and used for the scour.

=item B<pattern:> I<regex>

The Perl regular expression is used as the pattern with which to B<scour> the file.

=item B<execute:> I<command>

Execute the given command if all the constraints are met. The command may be enclosed
in single quotes.

=back

=head1 EXAMPLES

=over 4


=item B<example 1>

look for entries in log file with 'Authentication failure' that have been added in 
the last hour, and list the lines found

	scour -list previous:'01:00:00' pattern:'Authentication failure' file:'/var/log/system.log'

=item B<example 2>

look for shutdown entries that have occurred between two dates and return
a '0' or '1' if there have been more than three occasions

	scour -yesno from:'2005-11-11 00:00:00' to:'2005-11-15 23:59:59' num:4 \
		pattern:'shutdown: halt' file:'/var/log/system.log'

=item B<example 3>

look for at least three 'Failed su' messages within any 30 minute period
within the last 24 hours and if found list the matching lines to the terminal
and execute the command 'mail_alarm'

	scour -list within:00:30:30 pattern:'Failed su' file:'/var/log/auth.log' num:3 \
		 -nocase previous:24:00:00 execute:'/usr/local/mail_alarm -s "su failed"' 
 		
 
=back



=head1 AUTHOR

    David Scholefield
    david@port80.COM

=head1 AVAILABILITY

    Scour is available from 
    http://sourceforge.net/projects/log-scour/

=cut

use strict;
use HTTP::Date;
# set up variables to record results
my $found_count=0;
my @lines_found=();
my @found_dates=();
my @decreased_found_dates=();
my @debug_lines=();
my @within_lines=();

# set up variables to hold options
my $count_opt=0;
my $num_opt=0;
my $list_opt=0;
my $yesno_opt=0;
my $from_date=0;
my $verbose_opt=0;
my $case_flag=0;
my $execute_opt='none';
my $within_opt=0;
my $case_opt='regard case';
my $to_date=0;
my $filename='';
my $pattern='';
my $previous='';
my $is_prev=0;
my $from_to=0;

# some log files (snort alerts for example) don't have years
# we need to be able to add these
my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime(time); 
my $this_year=$year+1900;

# define patterns for date strings
my $month='Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec';
my $day = '[1-9][0-9]*';
my $time = '[0-9]{2}\:[0-9]{2}\:[0-9]{2}';

# define the patterns for various logs and the functions
# to convert the patterns into timestamps for str2time
# which expects YYYY-MM-DD HH:MM:SS

my %log_patterns = ();
my %log_functions = ();

define_patterns();

my @log_types = keys %log_patterns;

parse_opts();

# if the user enters a 'pling' before the filename it is
# to be treated as a shell command and the scour takes
# place against the execution of that command rather than
# a file - we check for this first

if ($filename =~ /^\!(.*)$/) {
	# we have a command to execute in order to generate the file!
	my $cmd=$1;
	print "executing command '$cmd'\n" if ($verbose_opt);
	my @results=`$cmd`;
	foreach my $line (@results)	{
			process_line($line, $from_date, $to_date, $pattern);
	}
	process_history() if ($within_opt);
	report();
}
else {
	if (open(InFile, "<$filename")) {
		while(my $line=<InFile>) {
			process_line($line, $from_date, $to_date, $pattern);
		}
		close(InFile);
		process_history() if ($within_opt);
		report();
	}
	else {
		print STDERR "Error! Failed to open file '$filename'\n";
		exit;
	}
}

exit;

sub process_line {

	my ($line, $fdate, $tdate, $pat) = @_;


	MATCH_LOG: foreach my $log_type (@log_types) {
		if ($line=~/$log_patterns{$log_type}/) {
			my $epoch=str2time($log_functions{$log_type}->($1));
			my $rest_line=$2;
	
			if ($epoch >= $fdate) {
				if ($epoch <= $tdate) {
					if (	(($line =~ /$pat/i) && $case_flag)
							||
							($line =~ /$pat/)
		     		   ) {
						$found_count++; 
						push @lines_found, $line;
						push @found_dates, $epoch; push @decreased_found_dates, $epoch; push @debug_lines, $line;
						print "INITIAL MATCH FOUND++ $line ++\n" if ($verbose_opt);
						 }
				}
			}
			last MATCH_LOG;
		}
		else {
			if ((!$is_prev && !$from_to) 
				&& 
				( (($line =~ /$pat/i) && $case_flag)
					||
					($line =~ /$pat/)
				)) {
					
					$found_count++; 
					push @lines_found, $line;
					# this seems non-sensical for no timestamp found! 
					# my $epoch = time(); 
					# push @found_dates, $epoch; 
					# push @decreased_found_dates, $epoch;
					push @debug_lines, $line;
					print "INITIAL MATCH FOUND++ $line ++\n" if ($verbose_opt);
				}
		}
	}
}

sub report {
	print "Num found: $found_count\n" if ($verbose_opt);
	if ($num_opt <= $found_count) {
		do_execute() if ($execute_opt ne 'none');

		if ($yesno_opt) { print "1"; exit;}
		else {
			list_found() if ($list_opt);
			exit if ($list_opt);
			print "$found_count\n" if ($count_opt);
			exit if ($count_opt);
		}
	}
	else {
		if ($yesno_opt)	{ print "0"; exit;}
		else {
			list_found() if ($list_opt);
			exit if ($list_opt);
			print "$found_count\n" if ($count_opt);
			exit if ($count_opt);
		}
	}
}

sub do_execute {
	print "Executing $execute_opt\n" if ($verbose_opt);
	$execute_opt=~s/\`\s*//; $execute_opt=~s/\s*\`$//;
	eval {
		`$execute_opt`;
	}
}

sub process_history
{
	# look at timestamps of matching lines
	# that are stored in @found_dates, and check
	# for number of matches within $within_op
	# period of seconds
	
	# set $found_count to number found to > $num if
	# a valid 'set' is found

	# we need to 'double loop' using each date as the
	# start of a new possible period
	
	# we will keep a record of the lines found
	# so that we can report which ones
	
	my $orig_line_index=0;
	my $orig_line_outer=-1;

	FINISH: foreach my $last_found  (@found_dates) {
		@within_lines=();
		$orig_line_outer++;
		$orig_line_index=$orig_line_outer;
		$found_count=1;
		shift @decreased_found_dates;
		push @within_lines, $debug_lines[$orig_line_outer];
		foreach my $current_date (@decreased_found_dates) {
			$orig_line_index++;
			if (($current_date - $last_found) < $within_opt) {	 
				$found_count++;
				push @within_lines, $debug_lines[$orig_line_index];
				# check to see if we have found the requisite number
				last FINISH if ($found_count == $num_opt);
		 	}
			else {
				next FINISH;
			}
		}
	}
}

sub list_found {
	
	if ($within_opt) {
		foreach my $line (@within_lines)
		{print $line;}
	}
	else {
		foreach my $line (@lines_found)
		{ print $line;}
	}
}

sub parse_opts
{
	# expecting 
	# from:'date string'
	# to:'date string'
	# file:'filename'
	# pattern:'pattern'
	# num:<number> (number of times pattern is expected)
	# -count (to give a count)
	# -list (to give a list)
	# -yesno (to return 0 or 1)
	# list, count, and yesno are mutually exclusive
	# previous:'times' defines the last n hours, mins, secs
	# in the format hh::mm::ss

	my $exclusive=0;
	my $exc_dates=0;

	
	ARG: foreach my $arg (@ARGV)
	{

		if ($arg =~ /-h/) {
			do_use();
			exit;
		}
		
		if ($arg =~ /file:\'?(.*)\'?/i) {
			$filename=$1;
			next ARG;
		}
		
		if ($arg =~ /previous:\'?([0-9]{2,})\:([0-9]{2})\:([0-9]{2})\'?/) {
			my ($hr, $mn, $sc) = ($1, $2, $3);
			my $nw=time();
			$to_date=$nw;
			$nw-=($hr*60*60);
			$nw-=($mn*60)+$sc;
			$from_date=$nw;
			$exc_dates++;
			$is_prev=1;
			next ARG;
		}
	
	
		if ($arg =~ /within:\'?([0-9]{2,})\:([0-9]{2})\:([0-9]{2})\'?/)	{
			my ($hr, $mn, $sc) = ($1, $2, $3);
			my $nw=($hr*60*60);
			$nw+=($mn*60)+$sc;
			$within_opt=$nw;
			next ARG;
		}
		
		if ($arg =~ /-nocase/) {
			$case_flag='i';
			$case_opt='ignore case';
			next ARG;
		}

		if ($arg =~ /-list/) {
			$list_opt=1;
			$exclusive++;
			next ARG;
		}
	
		if ($arg =~ /-v(?:erbose)?/) {
			$verbose_opt=1;
			next ARG;
		}
		
		if ($arg =~ /-count/) {
			$count_opt=1;
			$exclusive++;
			next ARG;
		}

		if ($arg =~ /-yesno/) {
			$yesno_opt=1;
			$exclusive++;
			next ARG;
		}
	
		if ($arg =~ /pattern:\'?(.*)\'?/i) {
			$pattern=$1;
			next ARG;
		}

		if ($arg =~ /num:\'?([0-9]+)\'?/i) {
			$num_opt=$1;
			next ARG;
		}

		if ($arg =~ /execute:(.*)/) {
			$execute_opt=$1;
			chomp $execute_opt;
			next ARG;
		}
	
		if ($arg =~ /from:\'?(.+)\'?/i) {
			$from_date=$1;
			$exc_dates++;
			$from_to=1;
			next ARG;
		}
	
		if ($arg =~ /to:\'?(.+)\'?/i) {
			$to_date=$1;
			$exc_dates++;
			$from_to=1;
			next ARG;
		}
		
		print "Don't understand option $arg\n";
		do_use();
		exit;
	}

	if (($is_prev) && ($exc_dates>1)) {
		print "use of previous mutually exclusive with\n";
		print "from: and to:\n";
		do_use();
		exit;
	}

	if ($exclusive>1) {
		print "use of count, list, and yesno options must\n";
		print "be exclusive\n";
		do_use();
		exit;
	}

	if (($from_date ne '0') && (!$is_prev)) {
		print "Converting from date '$from_date' to " if ($verbose_opt);
		$from_date=str2time($from_date);
		print "$from_date\n" if ($verbose_opt);
	}

	if ($to_date eq '0') { $to_date = '2037-12-31 23:59:59';}

	print "Converting to date '$to_date' to " if ($verbose_opt);
	$to_date=str2time($to_date) if (!$is_prev);
	print "$to_date\n" if ($verbose_opt);


	if ($verbose_opt) {
		print "Count option: $count_opt\n";
		print "Num option: $num_opt\n";
		print "List option: $list_opt\n";
		print "Yesno option: $yesno_opt\n";
		print "From date: $from_date\n";
		print "Within: $within_opt\n";
		print "Verbose option: $verbose_opt\n";
		print "To date: $to_date\n";
		print "Filename: $filename\n";
		print "Pattern: $pattern\n";
		print "Case: $case_opt\n";
		print "Execute: $execute_opt\n";
	}
}

sub define_patterns {
	
	$log_patterns{'syslog'} = '^'."((?:$month)".'\s+'."(?:$day)".'\s+'."(?:$time))".'\s+'."(.*)".'$';
	$log_patterns{'apache error'} = '^\[((?:[A-Za-z]{3}\s+)'."($month)".'\s+'."($day)".'\s+'."($time)".'(?:\s+2[0-9]{3}))\]\s+'."(.*)".'$';
	$log_patterns{'apache access'} = '^(?:[^\[]+)\[(\d{2}[^\[]+)\]\s+(.*)'.'$';
	$log_patterns{'snort_alert'} = '^(\d{2}\/\d{2}\s*\-\s*\d{2}\:\d{2}\:\d{2}\.\d+)\s+(.*)$';
	
	$log_functions{'syslog'} = sub { return shift; };
	$log_functions{'apache error'} = sub { return shift; };
	$log_functions{'apache access'} = sub { return shift; };
	$log_functions{'snort_alert'} = sub {
		my $in_date = shift;
		my ($mm, $dd, $hh, $mi, $ss);
		if ($in_date =~ /^(\d{2})\/(\d{2})\s*\-\s*(\d{2})\:(\d{2})\:(\d{2}\.\d+)/) {
			($mm, $dd, $hh, $mi, $ss) = ($1, $2, $3, $4, $5); 
		}
		# str2time wants form YYYY-MM-DD HH:MM:SS
		return $this_year.'-'.$mm.'-'.$dd.' '.$hh.':'.$mi.':'.$ss;
	}	
}

sub do_use
{
print<<ENDUSE

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

	scour -yesno from:'2005-11-11 00:00:00' to:'2005-11-15 23:59:59' num:4 \
		pattern:'shutdown: halt' file:'/var/log/system.log'
	
	3) Look for at least three 'Failed su' messages within any 30 minute period
	within the last 24 hours and if found list the matching lines to the terminal
	and execute the command 'mail_alarm'

	scour -list within:00:30:30 pattern:'Failed su' file:'/var/log/auth.log' num:3 \
		 -nocase previous:24:00:00 execute:'/usr/local/mail_alarm -s "su failed"' 
 		
ENDUSE
} 
