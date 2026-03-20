set -e

if [ -z "$1" ]
then
  echo "interface not supplied"
  exit 1
fi

MAC="$( ifconfig $1 | grep -m 1 ether | awk '{print $2}' )"
IP="$(ifconfig $1 | grep -m 1 'inet ' | awk '{print $2}')"
echo "$MAC,$IP"
