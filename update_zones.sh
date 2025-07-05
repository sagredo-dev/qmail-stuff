#!/bin/bash
#
# Roberto Puzzanghera https://notes.sagredo.eu
#
# Quickly updates serial, TTL, IP of bind zones
#
############################### Usage examples #####################################
#
# Update all zones incrementing their serial:
#
# ./update_zone.sh -a -s
#
# Update TTL and IP in a specific zone:
#
# ./update_zone.sh -t 3600 -o 10.1.1.10 -n 10.1.1.20 example.com
#
# Update IPs in all zones using defualt IPs:
#
# ./update_zone.sh -a
#
#####################################################################################

# Configuration options
BIND_CONF_DIR="/usr/local/etc/named"    # Path to BIND configuration directory
ZONE_DIR="$BIND_CONF_DIR/zones/EXT"     # Path to zone files
EXT=".conf"                             # Default file extension for zone files
SERIAL_STR=${SERIAL_STR:-serial}        # String used to locate the serial line in SOA
OWNER="named:named"                     # Owner:Group of the zones files
# Behavior control
NEW_TTL=""                              # TTL to set, if provided
BUMP_SERIAL=${BUMP_SERIAL:-false}       # Flag to increment SOA serial number
UPDATE_ALL=false                        # Flag to process all zone files
REPLACE_IP=${REPLACE_IP:-false}         # Replace IP only if requested
DATE=$(date +%Y%m%d)                    # Current date (used for serials)

# Default IPs to replace (can be overridden via -o/-n options)
NEW_IP="51.77.64.233"
OLD_IP="94.23.219.84"

# Print usage instructions
usage() {
    echo "Usage: $0 [-e extension] [-t TTL] [-s] [-a] [-o old_ip -n new_ip] [zonefile]"
    echo "  -e EXTENSION   Set the file extension (default: .conf)"
    echo "  -t TTL         Set a new TTL value (e.g., 3600)"
    echo "  -s             Increment the SOA serial number"
    echo "  -a             Update all zones in the directory"
    echo "  -o OLD_IP      IP address to search and replace (default: $OLD_IP)"
    echo "  -n NEW_IP      IP address to replace with (default: $NEW_IP)"
    echo "  zonefile       The zone file to update (without extension)"
    echo
    echo "To update IPs with the default values avoiding to use -o/-n values use like this:"
    echo "   REPLACE_IP=true $0 -s -a"
    exit 1
}

# Check if ZONE_DIR exists
if [ ! -d "$ZONE_DIR" ]; then
    echo "Error: ZONE_DIR '$ZONE_DIR' does not exist."
    exit 1
fi

# Parse options
while getopts "e:t:sao:n:" opt; do
    case "$opt" in
        e) EXT=".$OPTARG" ;;
        t) NEW_TTL="$OPTARG" ;;
        s) BUMP_SERIAL=true ;;
        a) UPDATE_ALL=true ;;
        o) OLD_IP="$OPTARG"; REPLACE_IP=true ;;
        n) NEW_IP="$OPTARG"; REPLACE_IP=true ;;
        *) usage ;;
    esac
done
shift $((OPTIND - 1))

# Determine which zone files to process
zones=()

if $UPDATE_ALL; then
    echo "Searching all zone files in: $ZONE_DIR"
    for f in "$ZONE_DIR"/*"$EXT"; do
        [ -f "$f" ] && zones+=("$(basename "$f" "$EXT")")
    done
    echo "Found ${#zones[@]} zone file(s) to process."
elif [ $# -ge 1 ]; then
    zones+=("$1")
else
    usage
fi

# Process each zone file
for name in "${zones[@]}"; do
    zonefile="$ZONE_DIR/$name$EXT"
    echo
    echo "Processing zone: $name"
    echo "Zone file: $zonefile"

    if [ ! -f "$zonefile" ]; then
        echo "  Error: File not found"
        continue
    fi

    modified=false
    tmpfile="$(mktemp)"
    cp "$zonefile" "$tmpfile"

    # Update TTL if requested
    if [ -n "$NEW_TTL" ]; then
        echo "  Updating TTL to $NEW_TTL"
        sed -i "1s/^[[:space:]]*[0-9]\{3,\}/$NEW_TTL/" "$tmpfile"
        modified=true
    else
        echo "  TTL update not requested"
    fi

    # Update serial if requested
    if $BUMP_SERIAL; then
        echo "  Incrementing serial..."
        current_serial=$(grep -E "^[[:space:]]*[0-9]+[[:space:]]*;[[:space:]]*$SERIAL_STR" "$tmpfile" \
                 | head -n1 | awk '{print $1}')
        if [ -z "$current_serial" ]; then
            echo "  Error: Serial not found"
        else
            serial_date=${current_serial:0:8}
            serial_seq=${current_serial:8:2}

            if [ "$serial_date" -lt "$DATE" ]; then
                new_serial="${DATE}01"
            else
                seq=$((10#$serial_seq + 1))
                new_serial="${serial_date}$(printf '%02d' $seq)"
            fi

            echo "  Old serial: $current_serial"
            echo "  New serial: $new_serial"
            sed -i "s/$current_serial/$new_serial/" "$tmpfile"
            modified=true
        fi
    else
        echo "  Serial update not requested"
    fi

    # Replace IPs if requested or using defaults
    if $REPLACE_IP; then
        if [[ -n "$OLD_IP" && -n "$NEW_IP" ]]; then
            if grep -q "$OLD_IP" "$tmpfile"; then
                echo "  Replacing IP: $OLD_IP -> $NEW_IP"
                sed -i "s/$OLD_IP/$NEW_IP/g" "$tmpfile"
                modified=true
            else
                echo "  IP $OLD_IP not found, skipping replacement"
            fi
        else
            echo "  IP replacement skipped: missing OLD_IP or NEW_IP"
        fi
    else
        echo "  IP replacement not requested"
    fi

    # Apply changes only if file was modified
    if cmp -s "$zonefile" "$tmpfile"; then
        echo "  No changes detected. Skipping overwrite."
        rm "$tmpfile"
    elif $modified; then
        echo "  Changes detected. Saving backup and updating file."
        cp "$zonefile" "$zonefile.bak"
        mv "$tmpfile" "$zonefile"
        chown $OWNER "$zonefile"
    else
        echo "  No relevant changes. Temporary file removed."
        rm "$tmpfile"
    fi

    echo "Finished processing $name"
done
