#!/bin/sh
set -eu

base_url="${MINIMAL_WAF_LAB_URL:-http://127.0.0.1:8088/}"
response_dir="$(mktemp -d)"
trap 'rm -r "$response_dir"' EXIT HUP INT TERM

check() {
    label="$1"
    expected="$2"
    path="$3"
    shift 3
    actual="$(curl --silent --show-error --max-time 10 --output "$response_dir/body" --dump-header "$response_dir/headers" --write-out '%{http_code}' "$@" "${base_url%/}$path")"
    if [ "$actual" != "$expected" ]; then
        printf '%s: got HTTP %s, expected %s\n' "$label" "$actual" "$expected" >&2
        exit 1
    fi
    if [ "$expected" = 403 ] && ! grep -qi '^X-Request-Id:' "$response_dir/headers"; then
        printf '%s: blocked response has no request ID\n' "$label" >&2
        exit 1
    fi
    if [ "$expected" = 403 ] && grep -q 'minimal-waf · security lab' "$response_dir/body"; then
        printf '%s: blocked response contains application HTML\n' "$label" >&2
        exit 1
    fi
    printf 'PASS %-20s HTTP %s\n' "$label" "$actual"
}

check 'home' 200 /
check 'benign SQL search' 200 / --request POST --data-urlencode 'term=Pen'
if ! grep -q 'Blue ballpoint pen' "$response_dir/body"; then
    printf 'benign SQL search: expected product not found\n' >&2
    exit 1
fi
check 'benign message' 200 / --get --data-urlencode 'message=Hello'
if ! grep -q '<p>Hello</p>' "$response_dir/body"; then
    printf 'benign message: reflected message not found\n' >&2
    exit 1
fi
check 'benign file' 200 / --get --data-urlencode 'file=welcome.txt'
if ! grep -q 'Welcome to the minimal-waf local security lab' "$response_dir/body"; then
    printf 'benign file: expected file content not found\n' >&2
    exit 1
fi
check 'SQLi blocked' 403 / --request POST --data-urlencode "term=' OR 1=1 -- "
check 'XSS blocked' 403 / --get --data-urlencode 'message=<script>alert(1)</script>'
check 'LFI blocked' 403 / --get --data-urlencode 'file=../../../../etc/passwd'
check 'operations hidden' 404 /_minimal-waf/healthz
