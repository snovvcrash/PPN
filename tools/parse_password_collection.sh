#!/bin/bash

: '
1) хедом смотрю, какие делиметры в файлах;
2) по делиметру откусываю последний столбец;
3) стрингсами выкидываю варианты меньше 5 символов;
4) регуляркой выкидываю варианты длиннее 31 символа.
'

for i in `ls | grep txt`; do
	cat $i | egrep "^.*@.*\.[a-zA-Z]{1,6}:.*$" | cut -d ":" -f 2- | strings -5 >> result
	cat $i | egrep "^.*@.*\.[a-zA-Z]{1,6};.*$" | cut -d ";" -f 2- | strings -5 >> result
	cat $i | egrep "^.*@.*\.[a-zA-Z]{1,6}\|.*$"| cut -d "|" -f 2- | strings -5 >> result
	cat $i | egrep -v "^.*@.*\.[a-zA-Z]{1,6}(;|:|\|).*$" >> nonmatch
	echo "[+] parsed: $i"
done
