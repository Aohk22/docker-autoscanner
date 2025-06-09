#!/usr/bin/env bash

VIRUS_TOTAL_API=""
MAIN_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPTS_DIR="${MAIN_DIR}/scripts"
AVRULES_DIR="${MAIN_DIR}/avrules"

Help() {
    echo "Usage: $0 [-h] [-s VT_API_KEY] File"
    echo Automate file static analysis for PE files using various command-line tools.
    echo
    echo Options:
    echo -e "h\tShow help."
    echo -e "s VT_API_KEY\tSubmits malware sample to VirusTotal for scanning."
    echo
}


getHashes() {
    local fn="$1"
    hash_md5="$(md5sum ${fn})"
    hash_sha1="$(sha1sum ${fn})"
    hash_sha256="$(sha256sum ${fn})"
    hash_ssdeep="$(ssdeep ${fn})"

    hash_parsed_md5="$(echo "${hash_md5}" | gawk '{ print $1 }')"
    hash_parsed_sha1="$(echo "${hash_sha1}" | gawk '{ print $1 }')"
    hash_parsed_sha256="$(echo "${hash_sha256}" | gawk '{ print $1 }')"
    hash_parsed_ssdeep="$(echo "${hash_ssdeep}" | gawk -v RS="" -v FS="\n" '{ print $2 }' | gawk -F "," '{ print $1 }')"

    echo HASHES
    echo -e "MD5\t:\t${hash_parsed_md5}\t${fn}"
    echo -e "SHA1\t:\t${hash_parsed_sha1}\t${fn}"
    echo -e "SHA256\t:\t${hash_parsed_sha256}\t${fn}"
    echo -e "SSdeep\t:\t${hash_parsed_ssdeep}\t${fn}"
}


getFileType() {
    local fn="$1"
    file_file="$(file ${fn})"
    file_trid="$(trid ${fn})"
    file_parsed_file="$(echo "${file_file}"} | gawk -F: '{ print $2 }')"
    file_parsed_trid="$(echo "${file_trid}" | grep -E '[[:digit:]]+\.[[:digit:]]%.+')"

    echo FILE TYPE
    echo -e "file\t:\t${file_file}"
    echo -e "trid\t:\n$(echo "${file_parsed_trid}" | gawk '{ print "\t" $0 }')"
}


getPeScanner() {
    local fn="$1"
    scan_pe=$(${SCRIPTS_DIR}/pescanner3.py ${fn} | tr -d '\0') # tr to disable null byte warning
    scan_parsed_pe_meta="$(echo "${scan_pe}" | gawk '/Meta-data|^Size|^Architecture|^Date|^CRC|^Language|^Entry/ { print $0 }')"
    scan_parsed_pe_section="$(echo "${scan_pe}"| gawk '/Sections|^Name|^\./ { print $0 }')"
    scan_parsed_pe_imports="$(echo "${scan_pe}" | gawk '/^Imports|^\[/ { print $0 }')"

    echo PE SCANNER RESULT
    echo -e "${scan_parsed_pe_meta}\n${scan_parsed_pe_section}\n${scan_parsed_pe_imports}"
}


getAVScan() {
    local fn="$1"
    av_scan_clamav=$(clamscan -d ${AVRULES_DIR}/clamav/ "${fn}")
    av_scan_yara=$(yara -r ${AVRULES_DIR}/yara/*.yar "${fn}")
    av_scan_clamav_parsed="$(echo "${av_scan_clamav}" | gawk 'NR == 1 { print $2 }')"
    av_scan_yara_parsed="$(echo "${av_scan_yara}" | gawk 'NR <= 3 { print $0 }')" # gets 3 results only

    echo AV SCAN RESULT
    echo -e "clamav:\t${fn}\t${av_scan_clamav_parsed}"
    echo -e "yara:\tTop results\n$(echo "${av_scan_yara_parsed:-"(No Yara scan output)"}" | gawk '{ print "\t" $0 }')"
}


getVTMultiAV() {
    local fn="$1"

    echo SCANNING USING VIRUSTOTAL API
    python3 "${SCRIPTS_DIR}/submitvt.py" "${fn}"
    # python3 "${SCRIPTS_DIR}/submitvt1.1.py" "${fn}"
}


# some interfaces
basicFileInfo() {
    local fn="$1"
    getHashes "${fn}"; echo
    getFileType "${fn}"; echo
    getPeScanner "${fn}"; echo
}


fileScan() {
    local fn="$1"
    local scan="$2"

    getAVScan "${fn}"; echo
    if [[ "${scan}" -eq 1 ]]; then
        getVTMultiAV "${fn}"; echo
    fi
}


# interface invoker
main() {
    # to the functions
    basicFileInfo "${filename}"
    fileScan "${filename}" "${vt_scan}"
}

vt_scan=0
while getopts ":hs:" option; do
    case $option in
        h)  Help; exit;;
        s)  vt_scan=1
            VIRUS_TOTAL_API="${OPTARG}"
            echo "VIRUS_TOTAL_API=${VIRUS_TOTAL_API}" > "${MAIN_DIR}/.env";;
        \?) echo "Error: Invalid option\n Use -h for help."; exit 1;;
        :)  echo "Option -${OPTARG} requires argument." >&2; exit 1;;
   esac
done
shift $((OPTIND - 1)) # get non opt arg

filename=${1:?No file provided}
file_path="$(pwd)/${filename}"
if [ ! -f "${file_path}" ]; then 
    echo "File not found at path ${file_path}"
    echo "Please use file name only (copy file into current folder.)"
    exit 1
fi

main
