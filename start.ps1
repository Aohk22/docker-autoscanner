if (-not $args[0]) {
    echo Provide docker image.
    exit /b
}

docker run --rm -it `
    -v '.\malware:/malware' `
    -v '.\output:/autoscanner/vt_output' `
    $args[0]
