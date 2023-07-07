#!/usr/bin/env bash

# This will send an example webhook notification.
# example power notification:       notification.sh -u https://example.com/webhook -s superSecret1
# example boot device notification: notification.sh -u https://example.com/webhook -s superSecret1 -p boot_device
# show the help:                    notification.sh -h

set -eo pipefail

hmac256 () {
    payload=$1
    secret=$2
    echo -n "X-Rufio-Signature-256: sha256=$(echo -n "$payload" | openssl sha256 -hmac "$secret" | sed 's/^.* //')"
}

hmac512 () {
    payload=$1
    secret=$2
    echo -n "X-Rufio-Signature-512: sha512=$(echo -n "$payload" | openssl sha512 -hmac "$secret" | sed 's/^.* //')"
}

power_payload () {
    host_ip="$1"
    task="$2"
cat <<EOF
{"host":"$host_ip","task":{"power":"$task"}}
EOF
}

next_device () {
    host_ip="$1"
    cat <<EOF
{"host":"$host_ip","task":{"bootDevice":{"device":"pxe"}}}
EOF
}

main() {
    url="$1"
    secret="$2"
    payload_type="$3"
    algo="$4"

    if [ "$payload_type" == "boot_device" ]; then
        data=$(next_device '192.168.2.3')
    else
        data=$(power_payload '192.168.2.3' 'on')
    fi
    d=$(date -I'seconds')
    if [ "$algo" == "sha512" ]; then
        sig=$(hmac512 "${data}${d}" "$secret")
    else
        sig=$(hmac256 "${data}${d}" "$secret")
    fi

    echo
    echo "=====Signature Payload Instructions======"
    echo "1. Create the timestamp header using RFC3339: 'X-Rufio-Timestamp: 2006-01-02T15:04:05Z07:00'"
    echo "2. Create a string by concatenating the HTTP request body and the timestamp header. There should not be any characters/delimeters in between concatenated strings."
    echo "3. HMAC sign (SHA256/SHA512) this string using the provided secret."
    echo "4. Hex encoded the HMAC signature (depending on the tool/language you use to HMAC sign this step could be redundant)."
    echo "5. Prepend the algorithm type and an equal sign to the hex encoded HMAC signature (sha256=)."
    echo "6. Store the signature in the signature header: 'X-Rufio-Signature: sha256=3ac3355...c9846"
    echo "=====Signature Payload Instructions======"
    echo
    echo "============Signature Details============"
    echo -e "body:\t\t\t${data}"
    echo -e "timestamp:\t\t${d}"
    echo -e "signature payload:\t${data}${d}"
    echo -e "signature header:\t${sig}"
    echo -e "timesteamp header:\tX-Rufio-Timestamp: ${d}"
    echo "============Signature Details============"
    echo
    echo "============Response Details============="
    curl "${url}" --data "${data}" -H "${sig}" -H "X-Rufio-Timestamp: ${d}" -H "Content-Type: application/vnd.api+json"
    echo "============Response Details============="  
}


usage() {
    cat <<USAGE

Usage: $0 [-u http://example.com/webhook] [-s superSecret1] [-p boot_device] [-a sha512]

Options:
    -u, --url:          webhook listener URL
    -s, --secret:       secret for HMAC signature
    -p, --payload:      payload type (default power)(power, boot_device)
    -a, --algo:         algorithm type (default sha256)(sha256, sha512)
USAGE
    exit 1
}

if [ $# -eq 0 ]; then
    usage
    exit 1
fi

URL=
SECRET=
PAYLOAD_TYPE=power
ALGO=sha256


while [ "$1" != "" ]; do
    case $1 in
    -u | --url)
        shift
        URL=$1
        ;;
    -s | --secret)
        shift # remove `-t` or `--tag` from `$1`
        SECRET=$1
        ;;
     -p | --payload)
        shift # remove `-t` or `--tag` from `$1`
        PAYLOAD_TYPE=$1
        ;;
    -a | --algo)
        shift # remove `-t` or `--tag` from `$1`
        ALGO=$1
        ;;
    -h | --help)
        usage # run usage function
        exit 0
        ;;
    *)
        usage
        exit 1
        ;;
    esac
    shift # remove the current value for `$1` and use the next
done

dependency_check() {
    failed=false
    for DEP in openssl curl date sed; do
        if ! command -v "$DEP" &>/dev/null; then
            echo "$DEP not found. Please make the '$DEP' command available in your PATH."
            failed=true
        fi
    done

    if [ "$failed" = true ]; then
        echo "failed dependency check"
        exit 1
    fi
}
dependency_check
main "$URL" "$SECRET" "$PAYLOAD_TYPE" "$ALGO"
