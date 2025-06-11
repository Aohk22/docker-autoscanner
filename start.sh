if [[ -z $1 ]]; then
    echo Provide docker image.
    exit 1
fi

docker run --rm -it \
    -v './malware:/malware' \
    -v './output:/autoscanner/vt_output' \
    $1
