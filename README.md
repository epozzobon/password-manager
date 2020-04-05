This password manager performs all encryption and decryption on the client
side.

The focus is on keeping the codebase small in order to make auditing easy.

It is assumed that the user trusts the computer, the browser and all
installed browser extensions before opening this page.

The passwords are contained in a JSON wallet like:
```
{
   passwords: [
     {"name": "google.com", "comment": "Username is example@gmail.com", secret: "qwerty123"},
     {"name": "yahoo.com", "comment": "Username is @example", secret: "asdf456"}
   ],
   signKey: "-----BEGIN PGP PRIVATE KEY BLOCK----\n\n....."
}
```

The wallet is encrypted by OpenPGP.js with a password provided by the user,
then it is signed using the private PGP key contained in wallet.signKey.
This signature is used to authenticate the user to the server, which knows
only the public key of the user stored in "users/$user/public.gpg".


