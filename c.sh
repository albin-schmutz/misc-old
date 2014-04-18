./npcc0 < ${1}.npl > ${1}-gen.c
if [ "$?" -ne "0" ]; then
  exit 1
fi
gcc -o np${1} ${1}-gen.c
#rm ${1}-gen.c
