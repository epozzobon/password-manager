#!/usr/bin/env bash

USER_ID=example
HOST=password.manager
USER_MAIL=$USER_ID@$HOST

export GNUPGHOME="$(mktemp -d)" || exit 1
[[ -d $GNUPGHOME ]] || exit 1
echo "\$GNUPGHOME is $GNUPGHOME"
echo "Press [Return] to continue, CTRL+C to abort:"
read

gpg --batch --passphrase '' --yes \
    --quick-gen-key $USER_MAIL

gpg --batch --armor -o $GNUPGHOME/private.gpg \
    --export-secret-keys $USER_MAIL

gpg --batch --armor -o $GNUPGHOME/public.gpg \
    --export $USER_MAIL

echo "{\"passwords\":[],\"signKey\": \"" > $GNUPGHOME/wallet.json
sed -e ':a;N;$!ba;s/\n/\\n/g' $GNUPGHOME/private.gpg >> $GNUPGHOME/wallet.json
echo "\"}" >> $GNUPGHOME/wallet.json
sed -e ':a;N;$!ba;s/\n//g' -i $GNUPGHOME/wallet.json

gpg -o $GNUPGHOME/wallet.json.gpg -c $GNUPGHOME/wallet.json
gpg -o $GNUPGHOME/payload.gpg --sign $GNUPGHOME/wallet.json.gpg

scp $GNUPGHOME/public.gpg $GNUPGHOME/payload.gpg root@$HOST:/var/www/html/passwords/users/$USER_ID/

echo "You should remove the temporary files with the following command"
echo "#rm -rf $GNUPGHOME"
