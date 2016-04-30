#!/bin/sh

# Written by Francois Gouget, fgouget@free.fr
# With many thanks to Daniel Martin and Falk Hueffner for their help
# Sux is released under the terms of the following license (X11 license)

# Copyright (c) 2001 Francois Gouget
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
# COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
# WHETHERIN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR 
# IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.


# How to transfer cookies for root. See the sux_cookie_transfer variable
# for options. Note that use-xauthority may not work if home directories
# are on NFS. In such a case, change the default to copy-cookies.
sux_root_cookie_transfer="c"


usage()
{
  echo "usage: `basename $0` [-m|-p|--preserve-environment]" >&2
  echo "           [--display display]" >&2
  echo "           [--no-cookies|--copy-cookies|--use-xauthority]" >&2
  echo "           [--untrusted] [--timeout x]" >&2
  echo "           [-] [username [command]]" >&2
  exit 2
}


##
# Process the sux options
sux_su_opts=""
sux_preserve=""
sux_got_minus=0
# "" -> default, n -> no-cookies, c -> copy-cookies, x -> use-xauthority
sux_cookie_transfer=""
sux_username=""
sux_untrusted=""
sux_timeout=""
while [ $# -gt 0 ]
do
  if [ "$sux_got_minus" = "1" ]
  then
    # Username follows "-"
    sux_username="$1"
    sux_su_opts="$sux_su_opts $1"
    shift
    # The remainder is the command to be executed
    break
  elif [ "$1" = "-" ]
  then
    # Last option before the username
    sux_su_opts="$sux_su_opts $1"
    sux_got_minus=1
    shift
  elif [ "$1" = "-m" -o "$1" = "-p" -o "$1" = "--preserve-environment" ]
  then
    sux_preserve="1"
    sux_su_opts="$sux_su_opts $1"
    shift
  elif [ "$1" = "--display" ]
  then
    if [ $# -lt 2 ]
    then
      echo "--display takes a display name as an argument" >&2
      usage # exits
    fi
    export DISPLAY="$2"
    shift 2
  elif [ "$1" = "--no-cookies" ]
  then
    if [ -n "$sux_cookie_transfer" -a "$sux_cookie_transfer" != "n" ]
    then
      echo "--no-cookies is incompatible with --copy-cookies and --use-xauthority" >&2
      usage # exits
    fi
    sux_cookie_transfer="n"
    shift
  elif [ "$1" = "--copy-cookies" ]
  then
    if [ -n "$sux_cookie_transfer" -a "$sux_cookie_transfer" != "c" ]
    then
      echo "--copy-cookies is incompatible with --no-cookies and --use-xauthority" >&2
      usage # exits
    fi
    sux_cookie_transfer="c"
    shift
  elif [ "$1" = "--use-xauthority" ]
  then
    if [ -n "$sux_cookie_transfer" -a "$sux_cookie_transfer" != "x" ]
    then
      echo "--use-xauthority is incompatible with --no-cookies and --copy-cookies" >&2
      usage # exits
    fi
    sux_cookie_transfer="x"
    shift
  elif [ "$1" = "--untrusted" ]
  then
    sux_untrusted="untrusted"
    shift
  elif [ "$1" = "--timeout" ]
  then
    if [ $# -lt 2 ]
    then
      echo "--timeout takes a timeout in seconds" >&2
      usage # exits
    fi
    sux_timeout="timeout $2"
    shift 2
  elif [ "$1" = "-?" ]
  then
    usage # exits
  else
    # First non-option is the username
    sux_username="$1"
    sux_su_opts="$sux_su_opts $1"
    shift
    # The remainder is the command to be executed
    break
  fi
done


##
# Get rid of the simple case
if [ -z "$DISPLAY" ]
then
  # If DISPLAY is not set we can take a shortcut...
  if [ -n "$sux_untrusted" -o -n "$sux_timeout" ]
  then
    echo "--untrusted and --timeout are only supported if DISPLAY is set" >&2
    usage #exits
  fi
  exec su $sux_su_opts "$@"
fi


##
# Do some option checking
if [ -z "$sux_username" ]
then
  sux_username="root"
fi
if [ -z "$sux_cookie_transfer" ]
then
  if [ "$sux_username" = "root" ]
  then
    sux_cookie_transfer="$sux_root_cookie_transfer"
  else
    sux_cookie_transfer="c"
  fi
fi
if [ "$sux_cookie_transfer" = "x" -a "$sux_username" != "root" ]
then
  echo "Only root can use --use-xauthority" >&2
  usage # exits
fi


##
# Create new cookies / retrieve the existing ones if necessary
if [ -n "$sux_untrusted" -o -n "$sux_timeout" ]
then
  if [ "$sux_cookie_transfer" != "c" ]
  then
    echo "--no-cookies/--use-xauthority are incompatible with --untrusted/--timeout" >&2
    usage #exits
  fi

  # Yeah, tempfile is a debian-specific command.  Workarounds exist for
  # other machines.  If you do use a workaround, be certain that said
  # workaround actually creates the new file, (via touch or similar) or
  # xauth (below) will produce a pointless warning message.
  sux_tmpfile=`tempfile -p sux`
  xauth -q -f $sux_tmpfile generate $DISPLAY . $sux_untrusted $sux_timeout
  sux_xauth_data=`xauth -f $sux_tmpfile nlist $DISPLAY`
  rm -f $sux_tmpfile
fi


## 
# Build the command to restore the cookies in the su
if [ "$sux_cookie_transfer" = "c" ]
then
  # --copy-cookies case. We copy the cookie(s) using the xauth command.

  # If display is of the form "host:x.y" we may also need to get the 
  # cookies for "host/unix:x.y".
  sux_unix_display=`echo $DISPLAY | sed -e 's#^\([a-zA-Z_.][a-zA-Z_.]*\):#\1/unix:#'`
  if [ "$DISPLAY" = "$sux_unix_display" ]
  then
    sux_unix_display=""
  fi

  # Get the cookies if we don't have them already
  if [ -z "$sux_xauth_data" ]
  then
    # Get the cookies. Note that we may need to 
    sux_xauth_data=`xauth -q nlist $DISPLAY`
    if [ -n "$sux_unix_display" ]
    then
      sux_xauth_data="$sux_xauth_data `xauth -q nlist $sux_unix_display`"
    fi
  fi

  # We highjack the TERM environment variable to transfer the cookies to the 
  # other user. We do this so that they never appear on any command line, and 
  # because TERM appears to be the only environment variable that is not 
  # reset by su. Then, as long as 'echo' is a shell builtin, these cookies 
  # will never appear as command line arguments which means noone will be 
  # able to intercept them (assuming they were safe in the first place).
  sux_term="TERM='$TERM'"
  # now we can store the script that will restore the cookies on the other 
  # side of the su, in TERM!

  # Remove the old cookies. They may cause trouble if we transfer only one 
  # cookie, e.g. an MIT cookie, and there's still a stale XDM cookie hanging 
  # around.
  export TERM="xauth -q remove $DISPLAY 2>/dev/null;"
  if [ -n "$sux_unix_display" ]
  then
    TERM="$TERM xauth -q remove $sux_unix_display;"
  fi

  # Note that there may be more than one cookie to transfer, hence 
  # this loop
  sux_i=0
  for sux_str in $sux_xauth_data
  do
    if [ $sux_i -eq 0 ]
    then
      TERM="$TERM echo $sux_str"
    else
      TERM="$TERM $sux_str"
    fi
    sux_i=`expr $sux_i + 1`
    if [ $sux_i -eq 9 ]
    then
      TERM="$TERM | xauth nmerge - ;"
      sux_i=0
    fi
  done
  sux_xauth_cmd="eval \$TERM;"
  sux_xauthority=""
elif [ "$sux_cookie_transfer" = "x" ]
then
  # --use-xauthority case. For root we can simplify things and simply 
  # access the original user's .Xauthority file.
  sux_term=""
  sux_xauth_cmd=""
  if [ -n "$XAUTHORITY" ]
  then
    sux_xauthority="XAUTHORITY='$XAUTHORITY'"
  else
    sux_xauthority="XAUTHORITY='$HOME/.Xauthority'"
  fi
else
  # --no-cookies case. We just transfer $DISPLAY and assume the 
  # target user already has the necessary cookies
  sux_term=""
  sux_xauth_cmd=""
  sux_xauthority=""
fi


##
# Marshall the specified command in an effort to support parameters that 
# contain spaces. This should be enough to get commands like 
# 'xterm -title "My XTerm"' to work.
sux_cmd=""
if [ $# -gt 0 ]
then
  while [ $# -gt 0 ]
  do
    sux_cmd="$sux_cmd \"$1\""
    shift
  done
elif [ "`basename $0`" = "suxterm" ]
then
  # Start an xterm, useful for temporary cookies
  sux_cmd=`which x-terminal-emulator`
  if [ -z "$sux_cmd" ]
  then
    sux_cmd="xterm"
  fi
else
  # If no command is specified, start a shell
  if [ $# -eq 0 ]
  then
    if [ "$sux_got_minus" = "1" ]
    then
      sux_cmd="sh -c \"exec -l \$SHELL\""
    else
      sux_cmd="\$SHELL"
    fi
  fi
fi


##
# We would not want the other user to try and use our XAUTHORITY file. He 
# wouldn't have the proper access rights anyway...
unset XAUTHORITY


##
# --preserve-environment special case
if [ -n "$sux_preserve" -a -n "$sux_xauth_cmd" ]
then
  sux_home=`egrep "^$sux_username:" /etc/passwd | cut -d: -f6`
  if [ -z "$sux_home" ]
  then
    echo "WARNING: --preserve-environment has been set, but no good value was found for XAUTHORITY, expect trouble" >&2
  else
    export XAUTHORITY="$sux_home/.Xauthority"
  fi
fi


##
# Execute su
exec su $sux_su_opts -c "$sux_xauth_cmd \
     exec env $sux_xauthority $sux_term DISPLAY='$DISPLAY' $sux_cmd;"
