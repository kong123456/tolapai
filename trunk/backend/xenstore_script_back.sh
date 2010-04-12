#!/bin/bash
if [ $# != 1 ]
then
        echo "Usage: $0 <frontend-id>"
else
	xenstore-write /local/domain/$1/device/ixp/0/state 1
	xenstore-write /local/domain/0/backend/ixp/$1/0/frontend-id $1
	xenstore-write /local/domain/0/backend/ixp/$1/0/frontend /local/domain/$1/device/ixp/0
	xenstore-write /local/domain/0/backend/ixp/$1/0/state 1
	xenstore-write /local/domain/0/backend/ixp/$1/0/physical-device 0
fi
