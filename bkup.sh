#!/bin/sh

DATE=`date "+%Y-%m-%dT%H_%M_%S"`
HOME="/root/"
#REMOTE_HOST="pluto.sidaf.local"
REMOTE_HOST="pluto"
REMOTE_PATH="/tank/backups"

rsync -a --no-owner -z -P -h \
 --delete \
 --delete-excluded \
 --exclude-from=$HOME/.rsync/exclude \
 --link-dest=../latest \
 $HOME $REMOTE_HOST:$REMOTE_PATH/incomplete-$DATE \
 && ssh $REMOTE_HOST \
 "mv $REMOTE_PATH/incomplete-$DATE $REMOTE_PATH/$DATE \
 && rm -f $REMOTE_PATH/latest \
 && ln -s $DATE $REMOTE_PATH/latest"
