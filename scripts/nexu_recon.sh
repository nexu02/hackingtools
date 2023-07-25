#!/bin/bash

### Herramienta de reconocimiento que automatiza comandos y genera reportes

source /root/tools/scripts/libs/nmap/nmap.lib

usage() {
	echo "Usage: $0 [ -n ] TARGETS"
	echo "-n -> Nmap syn scan (all ports)"
	exit 1
}

# Si no se especifica una opcion:
if [ "$#" -eq 0 ]; then
	usage
elif ! [[ "$1" =~ ^- ]]; then
	echo -e "You need to set an option\n"
	usage
fi

while getopts ":n" options; do
	TARGETS=()
	DIRECTORIES=()
	for i in "${@:$OPTIND:$#}"; do # Itera sobre los elementos ubicados despues de las opciones (targets)
		TARGETS+=("${i}")
	done
	targets_length="${#TARGETS[@]}" # Calcula la longitud del array con los targets
	if [ ${targets_length} -eq 0 ]; then # Si el array esta vacio
		echo "You need to set a target or targets."
		exit 1
	fi
	for (( i=0; $i<${targets_length}; i++ )); do # Si el array tiene un target, crea un directorio
		if ! [[ (( -d "$(pwd)/${TARGETS[$i]}" )) && (( -d "$(pwd)/${TARGETS[$i]}/recon" )) ]]; then
			echo "Creating directory $(pwd)/${TARGETS[${i}]}/recon for ${TARGETS[${i}]}"
			DIRECTORIES+=("$(pwd)/${TARGETS[${i}]}/recon")
			mkdir "$(pwd)/${TARGETS[${i}]}" && mkdir "$_/recon"
		else
			DIRECTORIES+=("$(pwd)/${TARGETS[$i]}/recon")
			echo "The results will save in ${TARGETS[$i]}/recon."
		fi
	done
	case "${options}" in
	  n)
	    syn_scan
	    ;;
	  :)
	    echo -e "Error: -${OPTARG} requires an argument.\n"
	    usage
	    ;;
	  *)
	    echo -e "This option is invalid.\n\n"
	    usage
	    ;;
	esac
	for (( i=0; $i<${targets_length}; i++)); do
		REP_DIR="${DIRECTORIES[$i]}/report"
		TAR_DIR="${DIRECTORIES[$i]}"
		TODAY=$(date)
		echo "Generating recon report for ${TARGETS[$i]}"
		echo -e "This scan was created on ${TODAY}\n" >> "${REP_DIR}"
		if [ -f "${TAR_DIR}/nmap" ]; then
			echo -e "Results for Nmap:\n" >> "${REP_DIR}"
			grep -E "^\s*\S+\s+\S+\s+\S+\s*$" "${TAR_DIR}/nmap" >> "${REP_DIR}"
			echo -e "\n\n" >> "${REP_DIR}"
		fi
	done
done
