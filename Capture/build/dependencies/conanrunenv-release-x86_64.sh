script_folder="/mnt/c/Users/102151/OneDrive - UNIPHORE SOFTWARE SYSTEMS PVT LTD/Documents/SIP_ENGINE/Capture/build/dependencies"
echo "echo Restoring environment" > "$script_folder/deactivate_conanrunenv-release-x86_64.sh"
for v in OPENSSL_MODULES
do
    is_defined="true"
    value=$(printenv $v) || is_defined="" || true
    if [ -n "$value" ] || [ -n "$is_defined" ]
    then
        echo export "$v='$value'" >> "$script_folder/deactivate_conanrunenv-release-x86_64.sh"
    else
        echo unset $v >> "$script_folder/deactivate_conanrunenv-release-x86_64.sh"
    fi
done


export OPENSSL_MODULES="/home/suyashgaurav72/.conan2/p/b/opens88671bfd44ecd/p/lib/ossl-modules"